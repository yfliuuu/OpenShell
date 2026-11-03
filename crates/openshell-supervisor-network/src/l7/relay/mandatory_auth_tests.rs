// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::opa::OpaEngine;
use openshell_core::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_supervisor_middleware::MiddlewareRegistry;
use openshell_supervisor_middleware_builtins::mandatory_auth::MandatoryAuthService;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn bindings() -> HashMap<String, StaticCredentialBinding> {
    HashMap::from([(
        "MYSERVICE_TOKEN".into(),
        StaticCredentialBinding {
            credential_identity: "provider:service_token".into(),
            endpoints: vec![StaticCredentialEndpointBinding {
                host: "api.myservice.example".into(),
                port: 8080,
                path: "/v1/**".into(),
            }],
            ..Default::default()
        },
    )])
}

fn state(token: &str) -> ProviderCredentialState {
    ProviderCredentialState::from_bound_environment(
        1,
        HashMap::from([("MYSERVICE_TOKEN".into(), token.into())]),
        HashMap::new(),
        HashMap::new(),
        bindings(),
        Vec::new(),
    )
    .unwrap()
}

async fn read_headers(stream: &mut DuplexStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        loop {
            let byte = stream.read_u8().await.unwrap();
            bytes.push(byte);
            if bytes.ends_with(b"\r\n\r\n") {
                return bytes;
            }
        }
    })
    .await
    .expect("HTTP header exchange must finish")
}

async fn exercise_live_authentication(initial: &str, inspected: bool) {
    let mut event_context = openshell_ocsf::ctx::ctx().clone();
    event_context.sandbox_id = "mandatory-auth-test".into();
    let _ = openshell_ocsf::ctx::set_ctx(event_context);
    let sandbox_id = openshell_ocsf::ctx::ctx().sandbox_id.clone();
    assert!(!sandbox_id.is_empty());
    let credentials = state(initial);
    let policy = openshell_policy::parse_sandbox_policy(
        r"
version: 1
network_middlewares:
  mandatory:
    middleware: acme/myservice-auth
    order: 2147483647
    on_error: fail_closed
    endpoints:
      include: [api.myservice.example]
    config:
      credential_env: MYSERVICE_TOKEN
      header_name: X-MyService-ID
network_policies:
  service:
    endpoints:
      - host: api.myservice.example
        port: 8080
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/curl
",
    )
    .unwrap();
    let engine = Arc::new(OpaEngine::from_proto(&policy).unwrap());
    let registry = MiddlewareRegistry::connect_services(
        vec![Arc::new(
            MandatoryAuthService::for_sandbox(sandbox_id, credentials.clone()).unwrap(),
        )],
        Vec::new(),
    )
    .await
    .unwrap();
    engine.replace_middleware_registry(registry).unwrap();
    let ctx = L7EvalContext {
        host: "api.myservice.example".into(),
        port: 8080,
        request_default_port: Some(if inspected { 443 } else { 80 }),
        policy_name: "service".into(),
        binary_path: "/usr/bin/curl".into(),
        provider_credentials: Some(credentials.clone()),
        ..Default::default()
    };
    let (endpoint, generation) = engine
        .query_endpoint_config_with_generation(&middleware_network_input(&ctx))
        .unwrap();
    let config = crate::l7::parse_l7_config(&endpoint.unwrap()).unwrap();
    let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
    let guard = tunnel.generation_guard().clone();
    let (mut app, mut client) = tokio::io::duplex(8192);
    let (mut upstream, mut service) = tokio::io::duplex(8192);
    let relay = tokio::spawn(async move {
        if inspected {
            relay_with_inspection(&config, tunnel, &mut client, &mut upstream, &ctx).await
        } else {
            relay_passthrough_with_credentials(
                &mut client,
                &mut upstream,
                &ctx,
                &guard,
                Some(&engine),
            )
            .await
        }
    });
    for input in [
        "",
        "X-MyService-ID: synthetic-b\r\n",
        "X-MYSERVICE-ID: first\r\nx-myservice-id: second\r\n",
        "X-MyService-ID: openshell:resolve:env:UNKNOWN\r\n",
    ] {
        let request =
            format!("GET /v1/items HTTP/1.1\r\nHost: api.myservice.example:8080\r\n{input}\r\n");
        app.write_all(request.as_bytes()).await.unwrap();
        let forwarded = read_headers(&mut service).await;
        let forwarded = std::str::from_utf8(&forwarded).unwrap();
        let values: Vec<_> = forwarded
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-myservice-id"))
            .map(|(_, value)| value.trim())
            .collect();
        assert_eq!(values, [initial]);
        service
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert!(read_headers(&mut app).await.starts_with(b"HTTP/1.1 200"));
    }
    credentials
        .install_bound_environment(
            2,
            HashMap::from([("MYSERVICE_TOKEN".into(), "synthetic-rotated".into())]),
            HashMap::new(),
            HashMap::new(),
            bindings(),
            Vec::new(),
        )
        .unwrap();
    app.write_all(b"GET /v1/items HTTP/1.1\r\nHost: api.myservice.example:8080\r\n\r\n")
        .await
        .unwrap();
    let forwarded = read_headers(&mut service).await;
    assert!(
        std::str::from_utf8(&forwarded)
            .unwrap()
            .contains("X-MyService-ID: synthetic-rotated\r\n")
    );
    service
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    assert!(read_headers(&mut app).await.starts_with(b"HTTP/1.1 200"));
    credentials.revoke_static_provider_environment(3);
    app.write_all(b"GET /v1/items HTTP/1.1\r\nHost: api.myservice.example:8080\r\nX-MyService-ID: synthetic-b\r\n\r\n").await.unwrap();
    assert!(!read_headers(&mut app).await.starts_with(b"HTTP/1.1 200"));
    tokio::time::timeout(Duration::from_secs(3), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut leaked = Vec::new();
    service.read_to_end(&mut leaked).await.unwrap();
    assert!(
        leaked.is_empty(),
        "revocation must not forward the client's alternative"
    );
}

#[tokio::test]
async fn mandatory_auth_overwrites_and_tracks_keep_alive_lifecycle() {
    for inspected in [false, true] {
        exercise_live_authentication("synthetic-a", inspected).await;
    }
}

#[tokio::test]
async fn mandatory_auth_concurrent_states_remain_isolated() {
    tokio::join!(
        exercise_live_authentication("synthetic-a", true),
        exercise_live_authentication("synthetic-b", true),
        exercise_live_authentication("synthetic-c", true),
    );
}

fn endpoint_rule_relay(
    engine: Arc<OpaEngine>,
    credentials: ProviderCredentialState,
    host: &str,
    inspected: bool,
) -> (
    DuplexStream,
    DuplexStream,
    tokio::task::JoinHandle<Result<()>>,
) {
    let ctx = L7EvalContext {
        host: host.into(),
        port: 8080,
        request_default_port: Some(if inspected { 443 } else { 80 }),
        policy_name: "service".into(),
        binary_path: "/usr/bin/curl".into(),
        provider_credentials: Some(credentials),
        ..Default::default()
    };
    let (endpoint, generation) = engine
        .query_endpoint_config_with_generation(&middleware_network_input(&ctx))
        .unwrap();
    let config = crate::l7::parse_l7_config(&endpoint.unwrap()).unwrap();
    let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
    let guard = tunnel.generation_guard().clone();
    let (app, mut client) = tokio::io::duplex(8192);
    let (mut upstream, service) = tokio::io::duplex(8192);
    let relay = tokio::spawn(async move {
        if inspected {
            relay_with_inspection(&config, tunnel, &mut client, &mut upstream, &ctx).await
        } else {
            relay_passthrough_with_credentials(
                &mut client,
                &mut upstream,
                &ctx,
                &guard,
                Some(&engine),
            )
            .await
        }
    });
    (app, service, relay)
}

async fn check_rule_headers(
    app: &mut DuplexStream,
    service: &mut DuplexStream,
    host: &str,
    header: &str,
    token: &str,
) {
    for input in [
        String::new(),
        format!("{header}: synthetic-foreign\r\n"),
        format!(
            "{}: first\r\n{}: second\r\n",
            header.to_ascii_uppercase(),
            header.to_ascii_lowercase()
        ),
        format!("{header}: openshell:resolve:env:UNKNOWN\r\n"),
    ] {
        app.write_all(
            format!("GET /v1/items?limit=1 HTTP/1.1\r\nHost: {host}:8080\r\n{input}\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let forwarded = read_headers(service).await;
        let forwarded = std::str::from_utf8(&forwarded).unwrap();
        let values = forwarded
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case(header))
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>();
        assert_eq!(values, [token]);
        assert!(!forwarded.contains("synthetic-foreign"));
        service
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert!(read_headers(app).await.starts_with(b"HTTP/1.1 200"));
    }
}

#[tokio::test]
async fn mandatory_auth_endpoint_rules_isolate_two_providers_on_live_connections() {
    for inspected in [false, true] {
        let mut event_context = openshell_ocsf::ctx::ctx().clone();
        event_context.sandbox_id = "mandatory-auth-test".into();
        let _ = openshell_ocsf::ctx::set_ctx(event_context);
        let mut all_bindings = bindings();
        let mut second_binding = all_bindings["MYSERVICE_TOKEN"].clone();
        second_binding.credential_identity = "provider2:service_token".into();
        second_binding.endpoints[0].host = "api.myservice2.example".into();
        all_bindings.insert("MYSERVICE2_TOKEN".into(), second_binding);
        let mut env = HashMap::from([
            ("MYSERVICE_TOKEN".into(), "synthetic-one".into()),
            ("MYSERVICE2_TOKEN".into(), "synthetic-two".into()),
        ]);
        let credentials = ProviderCredentialState::from_bound_environment(
            1,
            env.clone(),
            HashMap::new(),
            HashMap::new(),
            all_bindings.clone(),
            Vec::new(),
        )
        .unwrap();
        let policy = openshell_policy::parse_sandbox_policy(r"
version: 1
network_middlewares:
  mandatory:
    middleware: acme/myservice-auth
    order: 2147483647
    on_error: fail_closed
    endpoints:
      include: [api.myservice.example, api.myservice2.example]
    config:
      rules:
        - host: api.myservice.example
          port: 8080
          path: /v1/**
          credential_env: MYSERVICE_TOKEN
          header_name: X-MyService-ID
        - host: api.myservice2.example
          port: 8080
          path: /v1/**
          credential_env: MYSERVICE2_TOKEN
          header_name: X-MyService2-ID
network_policies:
  service:
    endpoints:
      - {host: api.myservice.example, port: 8080, protocol: rest, enforcement: enforce, access: full}
      - {host: api.myservice2.example, port: 8080, protocol: rest, enforcement: enforce, access: full}
    binaries:
      - path: /usr/bin/curl
").unwrap();
        openshell_supervisor_middleware_builtins::mandatory_auth::validate_policy(
            &policy,
            &HashMap::new(),
        )
        .unwrap();
        let engine = Arc::new(OpaEngine::from_proto(&policy).unwrap());
        let registry = MiddlewareRegistry::connect_services(
            vec![Arc::new(
                MandatoryAuthService::for_sandbox(
                    openshell_ocsf::ctx::ctx().sandbox_id.clone(),
                    credentials.clone(),
                )
                .unwrap(),
            )],
            Vec::new(),
        )
        .await
        .unwrap();
        engine.replace_middleware_registry(registry).unwrap();
        let (mut app1, mut service1, relay1) = endpoint_rule_relay(
            engine.clone(),
            credentials.clone(),
            "api.myservice.example",
            inspected,
        );
        let (mut app2, mut service2, relay2) = endpoint_rule_relay(
            engine,
            credentials.clone(),
            "api.myservice2.example",
            inspected,
        );
        tokio::join!(
            check_rule_headers(
                &mut app1,
                &mut service1,
                "api.myservice.example",
                "X-MyService-ID",
                "synthetic-one"
            ),
            check_rule_headers(
                &mut app2,
                &mut service2,
                "api.myservice2.example",
                "X-MyService2-ID",
                "synthetic-two"
            ),
        );
        env.insert("MYSERVICE_TOKEN".into(), "synthetic-rotated".into());
        credentials
            .install_bound_environment(
                2,
                env.clone(),
                HashMap::new(),
                HashMap::new(),
                all_bindings.clone(),
                Vec::new(),
            )
            .unwrap();
        tokio::join!(
            check_rule_headers(
                &mut app1,
                &mut service1,
                "api.myservice.example",
                "X-MyService-ID",
                "synthetic-rotated"
            ),
            check_rule_headers(
                &mut app2,
                &mut service2,
                "api.myservice2.example",
                "X-MyService2-ID",
                "synthetic-two"
            ),
        );
        env.remove("MYSERVICE_TOKEN");
        all_bindings.remove("MYSERVICE_TOKEN");
        credentials
            .install_bound_environment(
                3,
                env,
                HashMap::new(),
                HashMap::new(),
                all_bindings,
                Vec::new(),
            )
            .unwrap();
        app1.write_all(b"GET /v1/items HTTP/1.1\r\nHost: api.myservice.example:8080\r\nX-MyService-ID: synthetic-two\r\n\r\n").await.unwrap();
        assert!(!read_headers(&mut app1).await.starts_with(b"HTTP/1.1 200"));
        tokio::time::timeout(Duration::from_secs(3), relay1)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut leaked = Vec::new();
        service1.read_to_end(&mut leaked).await.unwrap();
        assert!(leaked.is_empty());
        check_rule_headers(
            &mut app2,
            &mut service2,
            "api.myservice2.example",
            "X-MyService2-ID",
            "synthetic-two",
        )
        .await;
        drop(app2);
        tokio::time::timeout(Duration::from_secs(3), relay2)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
