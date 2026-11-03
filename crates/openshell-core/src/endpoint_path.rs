// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical provider endpoint path matching shared by policy and runtime code.

/// A compiled provider endpoint path pattern.
///
/// Invalid glob syntax retains the existing fail-closed behavior: it matches
/// only when the request path is exactly equal to the configured pattern.
#[derive(Debug, Clone)]
pub struct EndpointPathPattern {
    source: String,
    kind: EndpointPathPatternKind,
}

#[derive(Debug, Clone)]
enum EndpointPathPatternKind {
    Any,
    Subtree(String),
    Glob(glob::Pattern),
    Invalid,
}

impl EndpointPathPattern {
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        let kind = if pattern.is_empty() || pattern == "**" || pattern == "/**" {
            EndpointPathPatternKind::Any
        } else if let Some(prefix) = pattern.strip_suffix("/**") {
            EndpointPathPatternKind::Subtree(prefix.to_string())
        } else {
            glob::Pattern::new(pattern).map_or(
                EndpointPathPatternKind::Invalid,
                EndpointPathPatternKind::Glob,
            )
        };
        Self {
            source: pattern.to_string(),
            kind,
        }
    }

    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        if self.source == path {
            return true;
        }
        match &self.kind {
            EndpointPathPatternKind::Any => true,
            EndpointPathPatternKind::Subtree(prefix) => {
                path == prefix
                    || path
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
            EndpointPathPatternKind::Glob(pattern) => pattern.matches(path),
            EndpointPathPatternKind::Invalid => false,
        }
    }

    /// Whether the pattern has valid syntax under endpoint matching semantics.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !matches!(self.kind, EndpointPathPatternKind::Invalid)
    }

    /// Conservatively determine whether two patterns may select the same path.
    ///
    /// Exact paths and subtrees can prove disjointness. General globs that
    /// cannot be compared exactly are treated as potentially overlapping.
    #[must_use]
    pub fn may_overlap(&self, other: &Self) -> bool {
        let literal = |pattern: &Self| {
            matches!(pattern.kind, EndpointPathPatternKind::Invalid)
                || matches!(pattern.kind, EndpointPathPatternKind::Glob(_))
                    && !pattern.source.contains(['*', '?', '['])
        };
        if literal(self) {
            return other.matches(&self.source);
        }
        if literal(other) {
            return self.matches(&other.source);
        }
        match (&self.kind, &other.kind) {
            (EndpointPathPatternKind::Subtree(left), EndpointPathPatternKind::Subtree(right)) => {
                self.matches(right) || other.matches(left)
            }
            _ => true,
        }
    }
}

/// Return whether `path` is selected by a provider endpoint path pattern.
///
/// Empty paths and `**` match every request path. A trailing `/**` matches the
/// named path itself and every descendant. Other patterns use glob semantics.
#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    EndpointPathPattern::new(pattern).matches(path)
}

#[cfg(test)]
mod tests {
    use super::{EndpointPathPattern, matches};

    #[test]
    fn endpoint_path_overlap_is_conservative_and_respects_subtree_boundaries() {
        for (left, right, expected) in [
            ("/**", "/v1/items", true),
            ("/v1/**", "/v1", true),
            ("/v1/**", "/v10/**", false),
            ("/v1/**", "/v2/**", false),
            ("/v1/**", "/v1/items/**", true),
            ("/v1/items", "/v1/other", false),
            ("/v*/items", "/v1/items", true),
            ("/v*/items", "/v1/other", false),
            ("/v*/items", "/other/*", true),
            ("/bad[", "/**", true),
        ] {
            let left = EndpointPathPattern::new(left);
            let right = EndpointPathPattern::new(right);
            assert_eq!(left.may_overlap(&right), expected);
            assert_eq!(right.may_overlap(&left), expected);
        }
        assert!(!EndpointPathPattern::new("/bad[").is_valid());
        assert!(EndpointPathPattern::new("/v*/items").is_valid());
    }

    #[test]
    fn matches_canonical_endpoint_patterns() {
        assert!(matches("", "/v1/messages"));
        assert!(matches("/**", "/v1/messages"));
        assert!(matches("/v1/**", "/v1"));
        assert!(matches("/v1/**", "/v1/messages"));
        assert!(matches("/v*/messages", "/v1/messages"));
        assert!(matches("/v1/*", "/v1/chat/messages"));
        assert!(!matches("/v1/**", "/v2/messages"));
        assert!(!matches("/v1/*/messages", "/v1/chat/completions"));
    }

    #[test]
    fn compiled_patterns_preserve_canonical_matching() {
        let subtree = EndpointPathPattern::new("/v1/**");
        assert!(subtree.matches("/v1"));
        assert!(subtree.matches("/v1/chat/messages"));
        assert!(!subtree.matches("/v2/messages"));

        let glob = EndpointPathPattern::new("/v*/messages");
        assert!(glob.matches("/v1/messages"));
        assert!(!glob.matches("/v1/completions"));

        let invalid = EndpointPathPattern::new("[");
        assert!(invalid.matches("["));
        assert!(!invalid.matches("/v1/messages"));
    }
}
