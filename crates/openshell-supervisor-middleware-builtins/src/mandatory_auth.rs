// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in mandatory static authentication for the `MyService` custom header.

use std::collections::HashMap;

use miette::{Result, miette};
use openshell_core::host_pattern::{HostPattern, HostSelector};
use openshell_core::middleware::{HttpRequestView, InProcessMiddleware, LocalHttpRequestResult};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestResult, MiddlewareBinding,
    MiddlewareManifest, ProviderProfileCredential, SandboxPolicy, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, WriteHeader, header_mutation,
};
use openshell_core::provider_credentials::ProviderCredentialState;
use serde::Deserialize;

pub const NAME: &str = "acme/myservice-auth";
const HEADER: &str = "X-MyService-ID";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub credential_env: String,
    pub header_name: String,
}

impl AuthConfig {
    pub fn from_struct(config: &prost_types::Struct) -> Result<Self> {
        let config: Self =
            serde_json::from_value(openshell_core::proto_struct::struct_to_json_value(config))
                .map_err(|_| {
                    miette!("mandatory authentication requires credential_env and header_name")
                })?;
        if config.credential_env.is_empty()
            || !config
                .credential_env
                .bytes()
                .enumerate()
                .all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphabetic()
                        || (index > 0 && byte.is_ascii_digit())
                })
            || !config.header_name.eq_ignore_ascii_case(HEADER)
        {
            return Err(miette!(
                "mandatory authentication requires a valid environment key and X-MyService-ID"
            ));
        }
        Ok(config)
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
            if !header.eq_ignore_ascii_case(&config.header_name) {
                continue;
            }
            let endpoint = openshell_core::dynamic_credential_key::endpoint_selector(key)
                .ok_or_else(|| {
                    miette!("dynamic grant scope is unavailable for mandatory authentication")
                })?;
            let host = HostPattern::new(endpoint.host)
                .map_err(|_| miette!("dynamic grant has an invalid endpoint host"))?;
            if selector.may_match_pattern(&host) {
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
        let captured = credentials
            .resolve_static_credential(&config.credential_env, &target.host, port, &target.path)
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
                        name: HEADER.into(),
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
