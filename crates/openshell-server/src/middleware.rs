// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::SandboxPolicy;
use openshell_supervisor_middleware::MiddlewareRegistry;
use tonic::Status;

/// Validate implementation-owned middleware config before accepting a policy.
pub async fn validate_policy(
    registry: &MiddlewareRegistry,
    policy: &SandboxPolicy,
) -> Result<(), Status> {
    #[cfg(feature = "mandatory-static-auth")]
    openshell_supervisor_middleware_builtins::mandatory_auth::validate_policy(
        policy,
        &std::collections::HashMap::new(),
    )
    .map_err(|error| Status::invalid_argument(error.to_string()))?;
    registry
        .validate_policy_configs(policy)
        .await
        .map_err(|error| {
            Status::invalid_argument(format!("policy middleware validation failed: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::NetworkMiddlewareConfig;

    #[cfg(feature = "mandatory-static-auth")]
    #[tokio::test]
    async fn mandatory_auth_admits_endpoint_rules_without_runtime_credentials() {
        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .unwrap();
        let mut policy = openshell_policy::parse_sandbox_policy(r"
version: 1
network_middlewares:
  mandatory:
    middleware: agent-guardrails/mandatory-auth
    order: 2147483647
    on_error: fail_closed
    endpoints:
      include: [api.service-1.com, api.service-2.com]
    config:
      rules:
        - {host: api.service-1.com, port: 443, path: '/**', credential_env: SERVICE_1_TOKEN, header_name: X-MyService-ID}
        - {host: api.service-2.com, port: 443, path: '/**', credential_env: SERVICE_2_TOKEN, header_name: X-MyService2-ID}
").unwrap();
        validate_policy(&registry, &policy).await.unwrap();
        policy
            .network_middlewares
            .get_mut("mandatory")
            .unwrap()
            .endpoints
            .as_mut()
            .unwrap()
            .include
            .pop();
        assert_eq!(
            validate_policy(&registry, &policy)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[cfg(feature = "mandatory-static-auth")]
    #[tokio::test]
    async fn mandatory_auth_validates_configuration_without_runtime_credentials() {
        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .unwrap();
        let mut policy = openshell_policy::parse_sandbox_policy(
            r"
version: 1
network_middlewares:
  mandatory:
    middleware: agent-guardrails/mandatory-auth
    order: 2147483647
    on_error: fail_closed
    endpoints:
      include: [api.myservice.example]
    config:
      credential_env: MYSERVICE_TOKEN
      header_name: X-MyService-ID
",
        )
        .unwrap();
        validate_policy(&registry, &policy).await.unwrap();
        policy
            .network_middlewares
            .get_mut("mandatory")
            .unwrap()
            .order = 0;
        assert_eq!(
            validate_policy(&registry, &policy)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn unregistered_external_middleware_is_rejected_before_admission() {
        let policy = SandboxPolicy {
            network_middlewares: std::collections::HashMap::from([(
                "guard".into(),
                NetworkMiddlewareConfig {
                    middleware: "example/content-guard".into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let error = validate_policy(&MiddlewareRegistry::default(), &policy)
            .await
            .expect_err("unregistered middleware must fail");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("not registered"));
    }

    #[tokio::test]
    async fn invalid_builtin_config_is_rejected_by_implementation() {
        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .expect("built-in registry");
        let policy = SandboxPolicy {
            network_middlewares: std::collections::HashMap::from([(
                "redactor".into(),
                NetworkMiddlewareConfig {
                    middleware: openshell_supervisor_middleware_builtins::BUILTIN_REGEX.into(),
                    config: Some(prost_types::Struct {
                        fields: std::iter::once((
                            "mode".into(),
                            prost_types::Value {
                                kind: Some(prost_types::value::Kind::StringValue("allow".into())),
                            },
                        ))
                        .collect(),
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let error = validate_policy(&registry, &policy)
            .await
            .expect_err("invalid built-in config must fail admission");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("supports only mode: redact"));
    }
}
