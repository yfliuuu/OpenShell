// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in endpoint-selected mandatory static authentication with custom headers.

use std::collections::HashMap;

use miette::{Result, miette};
use openshell_core::endpoint_path::EndpointPathPattern;
use openshell_core::host_pattern::{HostPattern, HostSelector};
use openshell_core::middleware::{
    HttpRequestView, InProcessMiddleware, LocalHttpRequestResult, is_protected_request_header,
    is_valid_http_header_name,
};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestResult, MiddlewareBinding,
    MiddlewareManifest, ProviderProfileCredential, SandboxPolicy, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, WriteHeader, header_mutation,
};
use openshell_core::provider_credentials::ProviderCredentialState;
use serde::Deserialize;

pub const NAME: &str = "agent-guardrails/mandatory-auth";
const MAX_RULES: usize = 64;

#[derive(Deserialize)]
#[serde(untagged)]
enum ConfigInput {
    Legacy(LegacyConfig),
    Rules(RulesConfig),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyConfig {
    credential_env: String,
    header_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesConfig {
    rules: Vec<RuleConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleConfig {
    host: String,
    #[serde(deserialize_with = "deserialize_port")]
    port: u16,
    path: String,
    credential_env: String,
    header_name: String,
}

fn deserialize_port<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    // Protobuf Struct represents all numbers, including integer ports, as doubles.
    let port = f64::deserialize(deserializer)?;
    if !(1.0..=f64::from(u16::MAX)).contains(&port) || port.fract() != 0.0 {
        return Err(serde::de::Error::custom("expected a port in 1-65535"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(port as u16)
}

#[derive(Debug)]
struct AuthEndpoint {
    host: HostPattern,
    port: u16,
    path: EndpointPathPattern,
}

impl AuthEndpoint {
    fn overlaps(&self, other: &Self) -> bool {
        self.port == other.port
            && self.host.overlaps(&other.host)
            && self.path.may_overlap(&other.path)
    }
}

#[derive(Debug)]
struct AuthRule {
    endpoint: Option<AuthEndpoint>,
    credential_env: String,
    header_name: String,
}

impl AuthRule {
    fn new(
        endpoint: Option<AuthEndpoint>,
        credential_env: String,
        header_name: String,
    ) -> Result<Self> {
        if credential_env.is_empty()
            || !credential_env.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            })
            || !is_valid_http_header_name(&header_name)
            || is_protected_request_header(&header_name)
        {
            return Err(miette!(
                "mandatory authentication requires a valid environment key and an unprotected custom header"
            ));
        }
        Ok(Self {
            endpoint,
            credential_env,
            header_name,
        })
    }
}

#[derive(Debug)]
pub struct AuthConfig {
    rules: Vec<AuthRule>,
}

impl AuthConfig {
    pub fn from_struct(config: &prost_types::Struct) -> Result<Self> {
        let input: ConfigInput =
            serde_json::from_value(openshell_core::proto_struct::struct_to_json_value(config))
                .map_err(|_| {
                    miette!("mandatory authentication requires either credential_env and header_name or endpoint rules")
                })?;
        let rules = match input {
            ConfigInput::Legacy(config) => vec![AuthRule::new(
                None,
                config.credential_env,
                config.header_name,
            )?],
            ConfigInput::Rules(config) => {
                if config.rules.is_empty() || config.rules.len() > MAX_RULES {
                    return Err(miette!(
                        "mandatory authentication requires 1-{MAX_RULES} rules"
                    ));
                }
                config
                    .rules
                    .into_iter()
                    .map(|rule| {
                        let host = HostPattern::new(&rule.host).map_err(|_| {
                            miette!("mandatory authentication rule host is invalid")
                        })?;
                        let path = EndpointPathPattern::new(&rule.path);
                        if rule.port == 0
                            || !rule.path.starts_with('/')
                            || rule.path.chars().any(char::is_control)
                            || !path.is_valid()
                        {
                            return Err(miette!(
                                "mandatory authentication rule port or path is invalid"
                            ));
                        }
                        AuthRule::new(
                            Some(AuthEndpoint {
                                host,
                                port: rule.port,
                                path,
                            }),
                            rule.credential_env,
                            rule.header_name,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?
            }
        };
        for (index, rule) in rules.iter().enumerate() {
            for previous in &rules[..index] {
                if rule
                    .endpoint
                    .as_ref()
                    .zip(previous.endpoint.as_ref())
                    .is_some_and(|(left, right)| left.overlaps(right))
                {
                    return Err(miette!("mandatory authentication rules overlap"));
                }
            }
        }
        Ok(Self { rules })
    }

    fn select(&self, host: &str, port: u16, path: &str) -> Result<&AuthRule> {
        let path = path.split_once('?').map_or(path, |(path, _)| path);
        let path = openshell_core::secrets::redact_target_for_policy(path)
            .map_err(|_| miette!("mandatory authentication request path is invalid"))?;
        let mut selected = None;
        for rule in &self.rules {
            if rule.endpoint.as_ref().is_some_and(|endpoint| {
                endpoint.port != port
                    || !endpoint.host.matches(host)
                    || !endpoint.path.matches(&path)
            }) {
                continue;
            }
            if selected.replace(rule).is_some() {
                return Err(miette!(
                    "mandatory authentication request matches multiple rules"
                ));
            }
        }
        selected.ok_or_else(|| miette!("mandatory authentication request matches no rule"))
    }
}

/// Validate desired configuration without requiring an available credential.
pub fn validate_policy<S: std::hash::BuildHasher>(
    policy: &SandboxPolicy,
    dynamic_credentials: &HashMap<String, ProviderProfileCredential, S>,
) -> Result<()> {
    for attachment in policy
        .network_middlewares
        .values()
        .filter(|entry| entry.middleware == NAME)
    {
        if attachment.order != i32::MAX
            || !matches!(attachment.on_error.as_str(), "" | "fail_closed")
        {
            return Err(miette!(
                "mandatory authentication requires maximum order and fail_closed"
            ));
        }
        let config = AuthConfig::from_struct(&attachment.config.clone().unwrap_or_default())?;
        let endpoints = attachment
            .endpoints
            .as_ref()
            .ok_or_else(|| miette!("mandatory authentication requires an endpoint selector"))?;
        let selector = HostSelector::new(&endpoints.include, &endpoints.exclude)
            .map_err(|_| miette!("mandatory authentication has an invalid endpoint selector"))?;
        for rule in &config.rules {
            if rule
                .endpoint
                .as_ref()
                .is_some_and(|endpoint| !selector.covers_pattern(&endpoint.host))
            {
                return Err(miette!(
                    "mandatory authentication rule host is not covered by its attachment"
                ));
            }
        }
        for (key, credential) in dynamic_credentials {
            if credential.token_grant.is_none() {
                continue;
            }
            let header = match credential.auth_style.trim().to_ascii_lowercase().as_str() {
                "" | "bearer" if credential.header_name.trim().is_empty() => "Authorization",
                "" | "bearer" | "header" => credential.header_name.trim(),
                _ => {
                    return Err(miette!(
                        "dynamic grant has unsupported authentication placement"
                    ));
                }
            };
            if !config
                .rules
                .iter()
                .any(|rule| header.eq_ignore_ascii_case(&rule.header_name))
            {
                continue;
            }
            let endpoint = openshell_core::dynamic_credential_key::endpoint_selector(key)
                .ok_or_else(|| {
                    miette!("dynamic grant scope is unavailable for mandatory authentication")
                })?;
            let host = HostPattern::new(endpoint.host)
                .map_err(|_| miette!("dynamic grant has an invalid endpoint host"))?;
            let port = endpoint
                .port
                .parse::<u16>()
                .map_err(|_| miette!("dynamic grant has an invalid endpoint port"))?;
            let path = EndpointPathPattern::new(endpoint.path);
            if selector.may_match_pattern(&host)
                && config.rules.iter().any(|rule| {
                    header.eq_ignore_ascii_case(&rule.header_name)
                        && rule.endpoint.as_ref().is_none_or(|endpoint| {
                            endpoint.port == port
                                && endpoint.host.overlaps(&host)
                                && endpoint.path.may_overlap(&path)
                        })
                })
            {
                return Err(miette!(
                    "dynamic grant conflicts with mandatory static authentication"
                ));
            }
        }
    }
    Ok(())
}

pub struct MandatoryAuthService {
    runtime: Option<(String, ProviderCredentialState)>,
}

impl MandatoryAuthService {
    #[must_use]
    pub fn validation_only() -> Self {
        Self { runtime: None }
    }

    pub fn for_sandbox(sandbox_id: String, credentials: ProviderCredentialState) -> Result<Self> {
        if sandbox_id.is_empty() {
            return Err(miette!(
                "mandatory authentication requires an immutable sandbox ID"
            ));
        }
        Ok(Self {
            runtime: Some((sandbox_id, credentials)),
        })
    }
}

#[async_trait::async_trait]
impl InProcessMiddleware for MandatoryAuthService {
    fn requires_credential_provenance(&self) -> bool {
        true
    }

    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: NAME.into(),
            service_version: openshell_core::VERSION.into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: 256 * 1024,
                request_timeout: None,
            }],
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                NAME,
                openshell_core::VERSION,
                [],
            )),
            ..Default::default()
        }
    }

    async fn validate_config(&self, name: &str, config: &prost_types::Struct) -> Result<()> {
        if name != NAME {
            return Err(miette!("unknown mandatory authentication implementation"));
        }
        AuthConfig::from_struct(config).map(|_| ())
    }

    async fn evaluate_http_request(&self, _: HttpRequestView<'_>) -> Result<HttpRequestResult> {
        Err(miette!(
            "mandatory authentication requires local provenance evaluation"
        ))
    }

    async fn evaluate_http_request_local(
        &self,
        request: HttpRequestView<'_>,
    ) -> Result<LocalHttpRequestResult> {
        let (sandbox_id, credentials) = self
            .runtime
            .as_ref()
            .ok_or_else(|| miette!("mandatory authentication runtime is unavailable"))?;
        if request.context().sandbox_id != *sandbox_id
            || request.middleware_name() != NAME
            || request.phase() != SupervisorMiddlewarePhase::PreCredentials
        {
            return Err(miette!(
                "mandatory authentication request identity is invalid"
            ));
        }
        let config = AuthConfig::from_struct(request.config())?;
        let target = request.target();
        let port = u16::try_from(target.port)
            .map_err(|_| miette!("mandatory authentication endpoint port is invalid"))?;
        let rule = config.select(&target.host, port, &target.path)?;
        let captured = credentials
            .resolve_static_credential(&rule.credential_env, &target.host, port, &target.path)
            .map_err(|_| miette!("mandatory authentication credential is unavailable"))?;
        if captured
            .value()
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
            || openshell_core::secrets::header_value_contains_reserved_credential_marker(
                captured.value(),
            )
        {
            return Err(miette!("mandatory authentication credential is unsafe"));
        }
        Ok(LocalHttpRequestResult {
            result: HttpRequestResult {
                decision: Decision::Allow as i32,
                header_mutations: vec![HeaderMutation {
                    operation: Some(header_mutation::Operation::Write(WriteHeader {
                        name: rule.header_name.clone(),
                        value: captured.value().into(),
                        on_existing: ExistingHeaderAction::Overwrite as i32,
                    })),
                }],
                ..Default::default()
            },
            credential_provenance: Some(captured.provenance().clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        HttpRequestTarget, MiddlewareEndpointSelector, NetworkMiddlewareConfig, RequestContext,
        StaticCredentialBinding, StaticCredentialEndpointBinding,
    };

    const HEADER: &str = "X-MyService-ID";

    fn from_json(value: serde_json::Value) -> prost_types::Struct {
        openshell_core::proto_struct::json_object_to_struct(value.as_object().unwrap().clone())
            .unwrap()
    }

    fn rules_json() -> serde_json::Value {
        serde_json::json!({"rules": [
            {"host": "api.example.com", "port": 443, "path": "/v1/**",
             "credential_env": "SERVICE_1_TOKEN", "header_name": HEADER},
            {"host": "api2.example.com", "port": 443, "path": "/v2/**",
             "credential_env": "SERVICE_2_TOKEN", "header_name": "X-MyService2-ID"}
        ]})
    }

    fn two_provider_bindings() -> HashMap<String, StaticCredentialBinding> {
        [
            ("SERVICE_1_TOKEN", "api.example.com", "/v1/**"),
            ("SERVICE_2_TOKEN", "api2.example.com", "/v2/**"),
        ]
        .into_iter()
        .map(|(key, host, path)| {
            (
                key.into(),
                StaticCredentialBinding {
                    credential_identity: format!("provider:{key}"),
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: host.into(),
                        port: 443,
                        path: path.into(),
                    }],
                    ..Default::default()
                },
            )
        })
        .collect()
    }

    async fn evaluate_rule(
        service: &MandatoryAuthService,
        config: &prost_types::Struct,
        host: &str,
        port: u32,
        path: &str,
    ) -> Result<LocalHttpRequestResult> {
        service
            .evaluate_http_request_local(HttpRequestView::new(
                SupervisorMiddlewarePhase::PreCredentials,
                &RequestContext {
                    sandbox_id: "sandbox-a".into(),
                    ..Default::default()
                },
                config,
                &HttpRequestTarget {
                    host: host.into(),
                    port,
                    path: path.into(),
                    ..Default::default()
                },
                &[],
                &[],
                NAME,
            ))
            .await
    }

    #[test]
    fn mandatory_auth_rule_configuration_is_bounded_and_unambiguous() {
        let valid = rules_json();
        AuthConfig::from_struct(&from_json(valid.clone())).unwrap();
        for (field, value) in [
            ("host", serde_json::json!("bad..host")),
            ("port", serde_json::json!(0)),
            ("port", serde_json::json!(-1)),
            ("port", serde_json::json!(65536)),
            ("port", serde_json::json!(443.5)),
            ("port", serde_json::json!("443")),
            ("path", serde_json::json!("relative")),
            ("path", serde_json::json!("/bad[")),
            ("credential_env", serde_json::json!("BAD=KEY")),
            ("header_name", serde_json::json!("Authorization")),
            ("header_name", serde_json::json!("Cookie")),
            ("header_name", serde_json::json!("Connection")),
            ("header_name", serde_json::json!("X-Amz-Date")),
            (
                "header_name",
                serde_json::json!("X-OpenShell-Credential-ID"),
            ),
            ("header_name", serde_json::json!("Bad Header")),
            ("header_name", serde_json::json!("X-Token\r\nInjected")),
            ("unknown", serde_json::json!("synthetic-config-value")),
        ] {
            let mut value_config = valid.clone();
            value_config["rules"][0][field] = value;
            let error = AuthConfig::from_struct(&from_json(value_config)).unwrap_err();
            assert!(!error.to_string().contains("synthetic-config-value"));
        }
        for value in [
            serde_json::json!({"rules": []}),
            serde_json::json!({"rules": valid["rules"], "credential_env": "TOKEN", "header_name": HEADER}),
            serde_json::json!({"rules": valid["rules"], "credential_env": null}),
            serde_json::json!({"rules": valid["rules"], "unknown": true}),
        ] {
            assert!(AuthConfig::from_struct(&from_json(value)).is_err());
        }
        let mut rules = Vec::new();
        for index in 0..MAX_RULES {
            let mut rule = valid["rules"][0].clone();
            rule["host"] = serde_json::json!(format!("api{index}.example.com"));
            rules.push(rule);
        }
        AuthConfig::from_struct(&from_json(serde_json::json!({"rules": rules}))).unwrap();
        let mut extra = valid["rules"][0].clone();
        extra["host"] = serde_json::json!("extra.example.com");
        rules.push(extra);
        assert!(AuthConfig::from_struct(&from_json(serde_json::json!({"rules": rules}))).is_err());
    }

    #[test]
    fn mandatory_auth_rule_selection_checks_host_port_path_and_query() {
        let config = AuthConfig::from_struct(&from_json(rules_json())).unwrap();
        assert_eq!(
            config
                .select("API.example.com", 443, "/v1?limit=1")
                .unwrap()
                .credential_env,
            "SERVICE_1_TOKEN"
        );
        assert_eq!(
            config
                .select("api2.example.com", 443, "/v2/items")
                .unwrap()
                .header_name,
            "X-MyService2-ID"
        );
        for (host, port, path) in [
            ("api.example.com", 8443, "/v1/items"),
            ("api.example.com", 443, "/v10/items"),
            ("other.example.com", 443, "/v1/items"),
            ("api.example.com", 443, "/V1/items"),
        ] {
            assert!(config.select(host, port, path).is_err());
        }
        let mut wildcard = rules_json();
        wildcard["rules"][0]["host"] = serde_json::json!("*.service-1.com");
        let config = AuthConfig::from_struct(&from_json(wildcard)).unwrap();
        assert!(config.select("API.service-1.com", 443, "/v1/items").is_ok());
        assert!(
            config
                .select("deep.api.service-1.com", 443, "/v1/items")
                .is_err()
        );
    }

    #[test]
    fn mandatory_auth_rejects_overlaps_without_first_match_precedence() {
        for (path, port, overlaps) in [
            ("/v1/**", 443, true),
            ("/v1/items", 443, true),
            ("/v*/items", 443, true),
            ("/v2/**", 443, false),
            ("/v1/**", 8443, false),
        ] {
            let mut rules = rules_json();
            rules["rules"][1]["host"] = serde_json::json!("*.example.com");
            rules["rules"][1]["path"] = serde_json::json!(path);
            rules["rules"][1]["port"] = serde_json::json!(port);
            assert_eq!(
                AuthConfig::from_struct(&from_json(rules)).is_err(),
                overlaps
            );
        }
        let raw = from_json(rules_json());
        let mut config = AuthConfig::from_struct(&raw).unwrap();
        config
            .rules
            .extend(AuthConfig::from_struct(&raw).unwrap().rules);
        assert!(config.select("api.example.com", 443, "/v1/items").is_err());
    }

    #[test]
    fn mandatory_auth_requires_outer_selector_coverage_and_checks_grants_per_rule() {
        let mut policy = policy();
        let attachment = policy.network_middlewares.get_mut("mandatory").unwrap();
        attachment.config = Some(from_json(rules_json()));
        assert!(validate_policy(&policy, &HashMap::new()).is_err());
        policy
            .network_middlewares
            .get_mut("mandatory")
            .unwrap()
            .endpoints
            .as_mut()
            .unwrap()
            .include = vec!["*.example.com".into()];
        validate_policy(&policy, &HashMap::new()).unwrap();
        for (host, port, path, header, conflict) in [
            ("*.example.com", 443, "/v1/**", "x-myservice-id", true),
            (
                "api2.example.com",
                443,
                "/v2/items",
                "x-myservice2-id",
                true,
            ),
            ("api.example.com", 443, "/v1/**", "X-MyService2-ID", false),
            ("api2.example.com", 443, "/v1/**", "X-MyService2-ID", false),
            ("api.example.com", 8443, "/v1/**", HEADER, false),
            ("other.example.com", 443, "/v1/**", HEADER, false),
        ] {
            let key = openshell_core::dynamic_credential_key::DynamicCredentialKey::new(
                host, port, path, "owner", "provider", "token",
            )
            .unwrap()
            .encode();
            let grants = HashMap::from([(
                key,
                ProviderProfileCredential {
                    auth_style: "header".into(),
                    header_name: header.into(),
                    token_grant: Some(
                        openshell_core::proto::ProviderCredentialTokenGrant::default(),
                    ),
                    ..Default::default()
                },
            )]);
            assert_eq!(validate_policy(&policy, &grants).is_err(), conflict);
        }
        policy
            .network_middlewares
            .get_mut("mandatory")
            .unwrap()
            .endpoints
            .as_mut()
            .unwrap()
            .exclude = vec!["api2.example.com".into()];
        assert!(validate_policy(&policy, &HashMap::new()).is_err());
    }

    #[tokio::test]
    async fn mandatory_auth_two_providers_select_custom_headers_and_revoke_independently() {
        let bindings = two_provider_bindings();
        let mut env = HashMap::from([
            ("SERVICE_1_TOKEN".into(), "synthetic-service1".into()),
            ("SERVICE_2_TOKEN".into(), "synthetic-service2".into()),
        ]);
        let state = ProviderCredentialState::from_bound_environment(
            1,
            env.clone(),
            HashMap::new(),
            HashMap::new(),
            bindings.clone(),
            Vec::new(),
        )
        .unwrap();
        let service = MandatoryAuthService::for_sandbox("sandbox-a".into(), state.clone()).unwrap();
        let config = from_json(rules_json());
        let first = evaluate_rule(&service, &config, "api.example.com", 443, "/v1/items")
            .await
            .unwrap();
        for (host, path, header, value) in [
            ("api.example.com", "/v1/items", HEADER, "synthetic-service1"),
            (
                "api2.example.com",
                "/v2/items",
                "X-MyService2-ID",
                "synthetic-service2",
            ),
        ] {
            let result = evaluate_rule(&service, &config, host, 443, path)
                .await
                .unwrap();
            let Some(header_mutation::Operation::Write(write)) =
                &result.result.header_mutations[0].operation
            else {
                panic!("expected overwrite")
            };
            assert_eq!(
                (&*write.name, &*write.value, write.on_existing),
                (header, value, ExistingHeaderAction::Overwrite as i32)
            );
            assert!(result.credential_provenance.is_some());
            assert!(!format!("{result:?}").contains(value));
        }
        env.insert("SERVICE_1_TOKEN".into(), "synthetic-rotated".into());
        state
            .install_bound_environment(
                2,
                env.clone(),
                HashMap::new(),
                HashMap::new(),
                bindings.clone(),
                Vec::new(),
            )
            .unwrap();
        assert!(
            first
                .credential_provenance
                .unwrap()
                .ensure_current(&state)
                .is_err()
        );
        let rotated = evaluate_rule(&service, &config, "api.example.com", 443, "/v1/items")
            .await
            .unwrap();
        assert!(
            matches!(&rotated.result.header_mutations[0].operation, Some(header_mutation::Operation::Write(write)) if write.value == "synthetic-rotated")
        );
        env.remove("SERVICE_1_TOKEN");
        let mut remaining_bindings = bindings;
        remaining_bindings.remove("SERVICE_1_TOKEN");
        state
            .install_bound_environment(
                3,
                env,
                HashMap::new(),
                HashMap::new(),
                remaining_bindings,
                Vec::new(),
            )
            .unwrap();
        assert!(
            evaluate_rule(&service, &config, "api.example.com", 443, "/v1/items")
                .await
                .is_err()
        );
        assert!(
            evaluate_rule(&service, &config, "api2.example.com", 443, "/v2/items")
                .await
                .is_ok()
        );
        let mut unauthorized = rules_json();
        unauthorized["rules"][0]["credential_env"] = serde_json::json!("SERVICE_2_TOKEN");
        assert!(
            evaluate_rule(
                &service,
                &from_json(unauthorized),
                "api.example.com",
                443,
                "/v1/items"
            )
            .await
            .is_err()
        );
    }

    fn config() -> prost_types::Struct {
        prost_types::Struct {
            fields: [
                (
                    "credential_env".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue(
                            "MYSERVICE_TOKEN".into(),
                        )),
                    },
                ),
                (
                    "header_name".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue(HEADER.into())),
                    },
                ),
            ]
            .into(),
        }
    }

    fn policy() -> SandboxPolicy {
        SandboxPolicy {
            network_middlewares: HashMap::from([(
                "mandatory".into(),
                NetworkMiddlewareConfig {
                    middleware: NAME.into(),
                    order: i32::MAX,
                    on_error: "fail_closed".into(),
                    config: Some(config()),
                    endpoints: Some(MiddlewareEndpointSelector {
                        include: vec!["api.example.com".into()],
                        exclude: Vec::new(),
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        }
    }

    #[test]
    fn mandatory_auth_rejects_malformed_configuration() {
        for (field, value) in [
            ("credential_env", ""),
            ("credential_env", "BAD=KEY"),
            ("header_name", "Authorization"),
            ("unknown", "synthetic-config-value"),
        ] {
            let mut config = config();
            config.fields.insert(
                field.into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(value.into())),
                },
            );
            let error = AuthConfig::from_struct(&config).unwrap_err();
            assert!(!error.to_string().contains("synthetic-config-value"));
        }
    }

    #[test]
    fn mandatory_auth_validates_order_failure_mode_and_overlapping_grants() {
        let mut policy = policy();
        validate_policy(&policy, &HashMap::new()).unwrap();
        for (order, on_error) in [(0, "fail_closed"), (i32::MAX, "fail_open")] {
            policy
                .network_middlewares
                .get_mut("mandatory")
                .unwrap()
                .order = order;
            policy
                .network_middlewares
                .get_mut("mandatory")
                .unwrap()
                .on_error = on_error.into();
            assert!(validate_policy(&policy, &HashMap::new()).is_err());
        }
        policy = self::policy();
        let key = openshell_core::dynamic_credential_key::DynamicCredentialKey::new(
            "*.example.com",
            443,
            "/**",
            "owner",
            "provider",
            "token",
        )
        .unwrap()
        .encode();
        let mut grants = HashMap::from([(
            key,
            ProviderProfileCredential {
                auth_style: "header".into(),
                header_name: "x-myservice-id".into(),
                token_grant: Some(openshell_core::proto::ProviderCredentialTokenGrant::default()),
                ..Default::default()
            },
        )]);
        assert!(validate_policy(&policy, &grants).is_err());
        grants.values_mut().next().unwrap().header_name = "Authorization".into();
        validate_policy(&policy, &grants).unwrap();
        grants.values_mut().next().unwrap().header_name = HEADER.into();
        policy
            .network_middlewares
            .get_mut("mandatory")
            .unwrap()
            .endpoints
            .as_mut()
            .unwrap()
            .exclude
            .push("api.example.com".into());
        validate_policy(&policy, &grants).unwrap();
    }

    #[tokio::test]
    async fn mandatory_auth_captures_current_identity_and_fails_closed_when_unavailable() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("MYSERVICE_TOKEN".into(), "synthetic-a".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "MYSERVICE_TOKEN".into(),
                StaticCredentialBinding {
                    credential_identity: "provider-a:service_token".into(),
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "api.example.com".into(),
                        port: 443,
                        path: "/v1/**".into(),
                    }],
                    ..Default::default()
                },
            )]),
            Vec::new(),
        )
        .unwrap();
        let service = MandatoryAuthService::for_sandbox("sandbox-a".into(), state.clone()).unwrap();
        let context = RequestContext {
            sandbox_id: "sandbox-a".into(),
            ..Default::default()
        };
        let target = HttpRequestTarget {
            host: "api.example.com".into(),
            port: 443,
            path: "/v1/items".into(),
            ..Default::default()
        };
        let config = config();
        let request = |context| {
            HttpRequestView::new(
                SupervisorMiddlewarePhase::PreCredentials,
                context,
                &config,
                &target,
                &[],
                &[],
                NAME,
            )
        };
        let result = service
            .evaluate_http_request_local(request(&context))
            .await
            .unwrap();
        let Some(header_mutation::Operation::Write(header)) =
            &result.result.header_mutations[0].operation
        else {
            panic!("expected overwrite")
        };
        assert_eq!(header.value, "synthetic-a");
        assert!(!result.result.has_body);
        assert!(result.credential_provenance.is_some());
        assert!(!format!("{result:?}").contains("synthetic-a"));
        assert!(
            service
                .evaluate_http_request(request(&context))
                .await
                .is_err()
        );
        assert!(
            MandatoryAuthService::validation_only()
                .evaluate_http_request_local(request(&context))
                .await
                .is_err()
        );
        let wrong_context = RequestContext {
            sandbox_id: "sandbox-b".into(),
            ..Default::default()
        };
        assert!(
            service
                .evaluate_http_request_local(request(&wrong_context))
                .await
                .is_err()
        );
        state.revoke_static_provider_environment(7);
        assert!(
            service
                .evaluate_http_request_local(request(&context))
                .await
                .is_err()
        );
    }
}
