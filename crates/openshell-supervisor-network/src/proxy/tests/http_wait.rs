// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::wait::WaitEnd;
use futures::poll;

// Every review in these ingress fixtures uses a simulated HeldProposalService;
// none exercises an actual manual-human decision or a live Gateway review RPC.
#[derive(Default)]
struct HeldIntentRecorder {
    metadata: std::sync::Mutex<Vec<String>>,
    decision: AtomicU32,
    observations: AtomicU32,
}

impl crate::l7::proposal::HeldProposalService for HeldIntentRecorder {
    fn observe<'a>(
        &'a self,
        workspace: &'a str,
        chunk_id: &'a str,
    ) -> crate::l7::proposal::ProposalObservation<'a> {
        Box::pin(async move {
            assert_eq!(workspace, "fixture-team");
            assert_eq!(chunk_id, "durable-fixture-chunk");
            self.observations.fetch_add(1, Ordering::Release);
            match self.decision.load(Ordering::Acquire) {
                0 => Ok(crate::l7::proposal::ReviewDecision::Pending),
                1 => Ok(crate::l7::proposal::ReviewDecision::Approved),
                2 => Ok(crate::l7::proposal::ReviewDecision::Rejected),
                3 => Err(crate::l7::proposal::ProposalSubmitError::Unavailable),
                4 => Err(crate::l7::proposal::ProposalSubmitError::Retryable),
                _ => unreachable!(),
            }
        })
    }

    fn submit<'a>(
        &'a self,
        input: &'a crate::l7::proposal::HeldProposalInput,
    ) -> crate::l7::proposal::ProposalSubmission<'a> {
        Box::pin(async move {
            assert_eq!(input.method(), "GET");
            assert_eq!(input.path(), "/missing");
            assert_eq!(input.workspace(), "fixture-team");
            assert_eq!(input.scope().endpoints.len(), 1);
            assert!(input.scope().endpoints[0].rules.is_empty());
            let metadata = input.review_metadata();
            for secret in [
                "query-sentinel",
                "header-sentinel",
                "cookie-sentinel",
                "proxy-auth-sentinel",
            ] {
                assert!(!metadata.contains(secret));
            }
            self.metadata.lock().unwrap().push(metadata);
            Ok("durable-fixture-chunk".into())
        })
    }
}

const HELD_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nheld-response!";

pub(super) fn assert_held_terminal_response(
    response: &[u8],
    status: u16,
    error: &str,
    reason: &str,
) {
    let boundary = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("held terminal must return an HTTP response, not EOF")
        + 4;
    let header = std::str::from_utf8(&response[..boundary]).unwrap();
    assert!(header.starts_with(&format!("HTTP/1.1 {status} ")));
    assert!(header.contains("Content-Type: application/json\r\n"));
    assert!(header.contains("Connection: close\r\n"));
    assert!(header.contains(&format!(
        "Content-Length: {}\r\n",
        response.len() - boundary
    )));
    let body: serde_json::Value = serde_json::from_slice(&response[boundary..]).unwrap();
    assert_eq!(body["error"], error);
    assert_eq!(body["reason"], reason);
    assert!(response.len() < 1024);
    for secret in [
        "query-sentinel",
        "header-sentinel",
        "cookie-sentinel",
        "proxy-auth-sentinel",
    ] {
        assert!(!String::from_utf8_lossy(response).contains(secret));
    }
}

async fn assert_no_held_dial(listener: &TcpListener) {
    let accept = listener.accept();
    tokio::pin!(accept);
    assert!(
        poll!(accept.as_mut()).is_pending(),
        "unexpected upstream connection"
    );
}

async fn drive_held_until<F: Future>(mut handler: std::pin::Pin<&mut F>, ready: impl Fn() -> bool) {
    while !ready() {
        assert!(
            poll!(handler.as_mut()).is_pending(),
            "handler exited while held"
        );
        tokio::task::yield_now().await;
    }
}

async fn read_held_close<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, tls: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    match stream.read_to_end(&mut bytes).await {
        Ok(_) => {}
        // Production drops retired TLS streams without close_notify. This is
        // transport EOF, not proof of a clean TLS shutdown.
        Err(error)
            if tls
                && matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
        Err(error) => panic!("reading held transport: {error}"),
    }
    bytes
}

async fn serve_held_once<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    destination: SocketAddr,
    tls: bool,
) {
    serve_held_once_with_credentials(stream, destination, tls, "header-sentinel", None).await;
}

async fn serve_held_once_with_credentials<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    stream: &mut S,
    destination: SocketAddr,
    tls: bool,
    authorization: &str,
    api_key: Option<&str>,
) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
        assert!(header.len() < 8192);
    }
    let header = String::from_utf8(header).unwrap();
    assert_eq!(
        header.lines().next(),
        Some("GET /missing?secret=query-sentinel HTTP/1.1")
    );
    assert!(header.contains(&format!("Host: {destination}\r\n")));
    for sentinel in ["query-sentinel", "cookie-sentinel"] {
        assert_eq!(header.matches(sentinel).count(), 1);
    }
    assert!(header.contains(&format!("Authorization: {authorization}\r\n")));
    assert_eq!(header.matches(authorization).count(), 1);
    assert_eq!(header.matches("Authorization:").count(), 1);
    if let Some(api_key) = api_key {
        assert!(header.contains(&format!("X-API-Key: {api_key}\r\n")));
    }
    assert!(header.contains("Cookie: cookie-sentinel\r\n"));
    assert!(!header.contains(secrets::PLACEHOLDER_PREFIX_PUBLIC));
    assert!(!header.contains(secrets::PROVIDER_ALIAS_MARKER_PUBLIC));
    let lower_header = header.to_ascii_lowercase();
    for forbidden in [
        "proxy-authorization:",
        "proxy-connection:",
        "proxy-authenticate:",
        "proxy-auth-sentinel",
        "x-proxy-hop:",
    ] {
        assert!(
            !lower_header.contains(forbidden),
            "proxy-only header or credential reached upstream: {forbidden}"
        );
    }
    stream.write_all(HELD_RESPONSE).await.unwrap();
    stream.flush().await.unwrap();
    // Keep the upstream alive until the one-shot relay drops it. Any replay
    // or second request on this same connection becomes an assertion failure.
    assert!(read_held_close(stream, tls).await.is_empty());
}

pub(super) fn held_proposal_context() -> Arc<PolicyLocalContext> {
    Arc::new(PolicyLocalContext::new(
        None,
        None,
        None,
        AgentProposals::default(),
        tokio::sync::watch::channel("fixture-team".to_string()).1,
    ))
}

#[tokio::test]
async fn explicit_and_virtual_connect_production_ingress_resume_once() {
    held_connect_resume_case(HeldConnectRoute::Direct).await;
}

#[tokio::test]
async fn plaintext_connect_resume_uses_upstream_proxy() {
    held_connect_resume_case(HeldConnectRoute::Proxy).await;
}

#[tokio::test]
async fn plaintext_connect_resume_honors_no_proxy() {
    held_connect_resume_case(HeldConnectRoute::NoProxy).await;
}

#[tokio::test]
async fn plaintext_connect_resume_proxy_rejection_never_falls_back() {
    held_connect_resume_case(HeldConnectRoute::ProxyRejectsResume).await;
}

#[derive(Clone, Copy, Debug)]
enum HeldConnectRoute {
    Direct,
    Proxy,
    NoProxy,
    ProxyRejectsResume,
}

impl HeldConnectRoute {
    fn proxied(self) -> bool {
        matches!(self, Self::Proxy | Self::ProxyRejectsResume)
    }
}

async fn answer_held_proxy_connect(stream: &mut TcpStream, destination: SocketAddr, reject: bool) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
        assert!(header.len() < 8192);
    }
    assert_eq!(
        header,
        format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes(),
        "corporate proxy must receive only CONNECT to the validated destination"
    );
    let response: &[u8] = if reject {
        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
    } else {
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    };
    stream.write_all(response).await.unwrap();
    stream.flush().await.unwrap();
}

async fn held_connect_resume_case(route: HeldConnectRoute) {
    held_connect_case(route, None).await;
}

#[tokio::test]
async fn plaintext_explicit_and_virtual_connect_terminal_responses_never_redial() {
    for end in [
        HeldForwardEnd::Rejected,
        HeldForwardEnd::Timeout,
        HeldForwardEnd::Unavailable,
    ] {
        held_connect_case(HeldConnectRoute::Direct, Some(end)).await;
    }
}

async fn held_connect_case(route: HeldConnectRoute, terminal: Option<HeldForwardEnd>) {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping CONNECT wait fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for virtual_connect in [false, true] {
            let listener = TcpListener::bind((ip, 0)).await.unwrap();
            let destination = listener.local_addr().unwrap();
            let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_proxy = UpstreamProxyConfig::from_args(&upstream_proxy::UpstreamProxyArgs {
                https_proxy: (!matches!(route, HeldConnectRoute::Direct))
                    .then(|| format!("http://{}", proxy_listener.local_addr().unwrap())),
                no_proxy: matches!(route, HeldConnectRoute::NoProxy)
                    .then(|| destination.to_string()),
                ..Default::default()
            }).unwrap();
            let data = policy_with_native_executable_paths(&format!(
                "network_policies:\n  fixture:\n    endpoints:\n      - host: \"{ip}\"\n        port: {port}\n        protocol: rest\n        enforcement: enforce\n        allowed_ips: [\"{ip}/32\"]\n        rules:\n          - allow: {{method: GET, path: /allowed}}\n    binaries:\n      - path: /usr/bin/curl\n",
                port = destination.port()
            ));
            let engine = Arc::new(
                native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data)
                    .unwrap(),
            );
            engine.set_http_hitl_wait_enabled(true);
            if let Some(end) = terminal { end.configure_deadline(&engine); }
            engine.attach_http_hitl_policy_observer();
            let recorder = Arc::new(HeldIntentRecorder::default());
            engine.set_http_hitl_proposal_service(recorder.clone());
            let cache = Arc::new(BinaryIdentityCache::new());
            let identity = ContractBinaryIdentity {
                executable: ContractExecutableIdentity {
                    path: executable_path("/usr/bin/curl"),
                    digest: Some("44".repeat(32).parse().unwrap()),
                },
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            };
            let (client, mut wire) = tokio::io::duplex(8192);
            let (stream, supplied_identity, socket_addrs, transparent) = if virtual_connect {
                let (decision, completion) = tokio::sync::oneshot::channel();
                let pending = PendingTcpOpen {
                    stream: Box::new(client),
                    binary_identity: Ok(identity),
                    destination,
                    socket: Some(
                        openshell_isolation_interface::contract::NetworkSocketMetadata {
                            socket_cookie: 7,
                            nonblocking: false,
                            process_generation: 1,
                        },
                    ),
                    policy_generation: engine.current_generation(),
                    timing: MediationTiming::default(),
                    decision,
                };
                let admitted = preauthorize_transparent_open(
                    pending, None, &engine, &cache, None, None, false, None,
                )
                .await
                .unwrap();
                assert_eq!(completion.await.unwrap(), TcpOpenDecision::RelayReady);
                admitted
            } else {
                let stream: BoundaryDuplexStream = Box::new(client);
                (stream, Some(Ok(identity)), None, None)
            };
            let ca = crate::l7::tls::SandboxCa::generate().unwrap();
            let config = Arc::new(
                openshell_crypto::tls::client_builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            );
            let tls = Arc::new(ProxyTlsState::new(
                crate::l7::tls::CertCache::new(ca),
                config,
            ));
            let header = format!("GET /missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n");
            let request = if virtual_connect {
                header
            } else {
                format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n{header}")
            };
            wire.write_all(request.as_bytes()).await.unwrap();
            let handler = Box::pin(handle_mediated_connection(
                tokio::io::BufReader::new(stream),
                supplied_identity,
                socket_addrs,
                transparent,
                None,
                engine.clone(),
                cache,
                Arc::new(AtomicU32::new(0)),
                Some(tls),
                Some(held_proposal_context()),
                AgentProposals::default(),
                Arc::new(None),
                Arc::new(None),
                Arc::new(upstream_proxy),
                None,
                None,
                None,
                None,
                None,
                None,
            ));
            tokio::pin!(handler);
            assert!(poll!(handler.as_mut()).is_pending());
            // The handler must continue polling DNS/connect while the test
            // awaits accept; merely polling it once can strand that future.
            let (expected, forbidden) = if route.proxied() {
                (&proxy_listener, &listener)
            } else {
                (&listener, &proxy_listener)
            };
            let (mut upstream, _) = tokio::select! {
                accepted = expected.accept() => accepted.unwrap(),
                _ = forbidden.accept() => panic!("initial CONNECT used wrong route: {route:?}"),
                result = handler.as_mut() => panic!("CONNECT exited before upstream accept: {result:?}"),
            };
            if route.proxied() {
                let handshake = answer_held_proxy_connect(&mut upstream, destination, false);
                tokio::pin!(handshake);
                tokio::select! {
                    () = handshake.as_mut() => {},
                    result = handler.as_mut() => panic!("CONNECT exited during proxy handshake: {result:?}"),
                }
            }
            while engine.http_hitl_wait_runtime().population() == 0 {
                assert!(poll!(handler.as_mut()).is_pending());
                tokio::task::yield_now().await;
            }
            let sent = tokio::select! {
                sent = read_held_close(&mut upstream, false) => sent,
                result = handler.as_mut() => panic!("CONNECT exited while Pending: {result:?}"),
            };
            assert!(sent.is_empty());
            assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
            if !virtual_connect {
                let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                let mut response = vec![0; expected.len()];
                tokio::select! {
                    result = wire.read_exact(&mut response) => { result.unwrap(); },
                    result = handler.as_mut() => panic!("CONNECT exited before envelope response: {result:?}"),
                }
                assert_eq!(response, expected);
            }
            if let Some(end) = terminal {
                recorder.decision.store(end.decision(), Ordering::Release);
                engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data.replace("path: /allowed", "path: /missing")).unwrap();
                let client = async { read_held_close(&mut wire, false).await };
                let (result, response) = tokio::join!(handler, client);
                result.unwrap();
                end.assert_response(&response);
                for listener in [listener, proxy_listener] {
                    assert_eq!(listener.into_std().unwrap().accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
                }
                assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
                assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
                continue;
            }
            engine
                .reload(include_str!("../../../data/sandbox-policy.rego"), &data)
                .unwrap();
            let observations = recorder.observations.load(Ordering::Acquire);
            drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
            assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
            assert_no_held_dial(&listener).await;
            assert_no_held_dial(&proxy_listener).await;
            recorder.decision.store(1, Ordering::Release);
            let observations = recorder.observations.load(Ordering::Acquire);
            engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data).unwrap();
            drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
            assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
            assert_no_held_dial(&listener).await;
            assert_no_held_dial(&proxy_listener).await;
            engine
                .reload(
                    include_str!("../../../data/sandbox-policy.rego"),
                    &data.replace("path: /allowed", "path: /missing"),
                )
                .unwrap();
            let server = async {
                let (mut fresh, _) = tokio::select! {
                    accepted = expected.accept() => accepted.unwrap(),
                    _ = forbidden.accept() => panic!("resumed CONNECT bypassed configured route: {route:?}"),
                };
                let reject = matches!(route, HeldConnectRoute::ProxyRejectsResume);
                if route.proxied() {
                    answer_held_proxy_connect(&mut fresh, destination, reject).await;
                }
                if reject {
                    assert!(read_held_close(&mut fresh, false).await.is_empty(),
                        "proxy rejection must not release HTTP bytes");
                } else {
                    serve_held_once(&mut fresh, destination, false).await;
                }
            };
            let client = async {
                let response = read_held_close(&mut wire, false).await;
                if matches!(route, HeldConnectRoute::ProxyRejectsResume) {
                    assert!(response.is_empty(), "rejected proxy tunnel must retire the original client");
                } else {
                    assert_eq!(response, HELD_RESPONSE);
                }
            };
            let (result, (), ()) = tokio::join!(handler, server, client);
            // The native CONNECT adapter logs relay failures and returns Ok
            // after retiring the client. Peer bytes and both backlogs below,
            // not its return value, prove rejection without direct fallback.
            result.unwrap();
            for listener in [listener, proxy_listener] {
                assert_eq!(listener.into_std().unwrap().accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock, "no extra dial or direct fallback");
            }
            assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
            assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("explicit/virtual CONNECT must resume exactly once and close: {route:?}"));
}

#[tokio::test]
async fn forward_production_ingress_resume_once_without_early_dial() {
    held_forward_resume_case("", false).await;
}

#[tokio::test]
async fn forward_production_ingress_resume_keeps_native_direct_route() {
    held_forward_resume_case("", true).await;
}

#[tokio::test]
async fn forward_production_ingress_resume_strips_proxy_credentials() {
    held_forward_resume_case(
        concat!(
            "Proxy-Authorization: Basic proxy-auth-sentinel\r\n",
            "pRoXy-AuThOrIzAtIoN: Basic repeated-proxy-auth-sentinel\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "pRoXy-AuThEnTiCaTe: Basic realm=proxy-auth-sentinel\r\n",
            "Connection: X-Proxy-Hop\r\n",
            "X-Proxy-Hop: proxy-auth-sentinel\r\n",
        ),
        false,
    )
    .await;
}

async fn held_forward_resume_case(proxy_headers: &str, configure_proxy: bool) {
    held_forward_credential_case(proxy_headers, configure_proxy, None).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldForwardCredential {
    Valid,
    Unknown,
    EndpointMismatch,
    Revoked,
}

#[tokio::test]
async fn forward_resume_resolves_application_placeholders_and_strips_proxy_headers() {
    held_forward_credential_case(
        "Proxy-Authorization: Basic proxy-auth-sentinel\r\nProxy-Connection: keep-alive\r\nProxy-Authenticate: Basic proxy-auth-sentinel\r\nConnection: X-Proxy-Hop\r\nX-Proxy-Hop: proxy-auth-sentinel\r\n",
        false,
        Some(HeldForwardCredential::Valid),
    )
    .await;
}

#[tokio::test]
async fn forward_resume_rejects_unknown_mismatched_and_revoked_placeholders() {
    for credential in [
        HeldForwardCredential::Unknown,
        HeldForwardCredential::EndpointMismatch,
        HeldForwardCredential::Revoked,
    ] {
        held_forward_credential_case("", false, Some(credential)).await;
    }
}

async fn held_forward_credential_case(
    proxy_headers: &str,
    configure_proxy: bool,
    credential: Option<HeldForwardCredential>,
) {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping FORWARD resume fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let upstream = TcpListener::bind((ip, 0)).await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let credentials = credential.map(|kind| {
            use openshell_core::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
            ProviderCredentialState::from_bound_environment(
                1,
                std::collections::HashMap::from([("API_KEY".into(), "held-fixture-token".into())]),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                std::collections::HashMap::from([(
                    "API_KEY".into(),
                    StaticCredentialBinding {
                        credential_identity: "held-fixture:API_KEY".into(),
                        workload_credential_handle: String::new(),
                        endpoints: vec![StaticCredentialEndpointBinding {
                            host: ip.to_string(),
                            port: u32::from(destination.port()),
                            path: if kind == HeldForwardCredential::EndpointMismatch {
                                "/other".into()
                            } else {
                                "/missing".into()
                            },
                        }],
                    },
                )]),
                Vec::new(),
            )
            .unwrap()
        });
        let placeholder = credentials.as_ref().map(|state| {
            if credential == Some(HeldForwardCredential::Unknown) {
                "openshell:resolve:env:MISSING_KEY".to_owned()
            } else {
                state.snapshot().child_env["API_KEY"].clone()
            }
        });
        let authorization = placeholder.as_ref().map_or_else(
            || "header-sentinel".to_owned(),
            |placeholder| format!("Bearer {placeholder}"),
        );
        let application_headers = placeholder.as_ref().map_or_else(String::new, |placeholder| {
            format!(
                "X-API-Key: provider-OPENSHELL-RESOLVE-ENV-{}\r\n",
                placeholder.strip_prefix(secrets::PLACEHOLDER_PREFIX_PUBLIC).unwrap()
            )
        });
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_proxy = UpstreamProxyConfig::from_args(&upstream_proxy::UpstreamProxyArgs {
            https_proxy: configure_proxy
                .then(|| format!("http://{}", proxy_listener.local_addr().unwrap())),
            ..Default::default()
        }).unwrap();
        let data = policy_with_native_executable_paths(&format!(
            "network_policies:\n  fixture:\n    endpoints:\n      - host: \"{ip}\"\n        port: {port}\n        protocol: rest\n        enforcement: enforce\n        allowed_ips: [\"{ip}/32\"]\n        rules:\n          - allow: {{method: GET, path: /allowed}}\n    binaries:\n      - path: /usr/bin/curl\n",
            port = destination.port()
        ));
        let engine = Arc::new(
            native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data)
                .unwrap(),
        );
        engine.set_http_hitl_wait_enabled(true);
        engine.attach_http_hitl_policy_observer();
        let recorder = Arc::new(HeldIntentRecorder::default());
        engine.set_http_hitl_proposal_service(recorder.clone());
        let identity = ContractBinaryIdentity {
            executable: ContractExecutableIdentity {
                path: executable_path("/usr/bin/curl"),
                digest: Some("44".repeat(32).parse().unwrap()),
            },
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let (client, mut wire) = tokio::io::duplex(8192);
        let request = format!(
            "GET http://{destination}/a/../missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: {authorization}\r\nCookie: cookie-sentinel\r\n{application_headers}{proxy_headers}\r\n"
        );
        let handler = Box::pin(handle_mediated_connection(
            tokio::io::BufReader::new(Box::new(client)),
            Some(Ok(identity)),
            None,
            None,
            None,
            engine.clone(),
            Arc::new(BinaryIdentityCache::new()),
            Arc::new(AtomicU32::new(0)),
            None,
            Some(held_proposal_context()),
            AgentProposals::default(),
            Arc::new(None),
            Arc::new(None),
            Arc::new(upstream_proxy),
            credentials.clone(),
            None,
            None,
            None,
            None,
            None,
        ));
        tokio::pin!(handler);
        // Exercise the real initial capture boundary, not the test-only
        // FORWARD wrapper that creates its slot after capture.
        let boundary = request.len() / 2;
        wire.write_all(&request.as_bytes()[..boundary])
            .await
            .unwrap();
        assert!(poll!(handler.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        wire.write_all(&request.as_bytes()[boundary..])
            .await
            .unwrap();
        assert!(poll!(handler.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
        assert_no_held_dial(&upstream).await;
        engine
            .reload(include_str!("../../../data/sandbox-policy.rego"), &data)
            .unwrap();
        let observations = recorder.observations.load(Ordering::Acquire);
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_no_held_dial(&upstream).await;
        // Coverage alone is not approval. Observe the installed rule while
        // the deterministic reviewer still reports Pending.
        // First verify the converse: approval cannot release an uncovered
        // request or prepare application credentials for forwarding.
        recorder.decision.store(1, Ordering::Release);
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data).unwrap();
        let observations = recorder.observations.load(Ordering::Acquire);
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_no_held_dial(&upstream).await;
        recorder.decision.store(0, Ordering::Release);
        engine
            .reload(
                include_str!("../../../data/sandbox-policy.rego"),
                &data.replace("path: /allowed", "path: /missing"),
            )
            .unwrap();
        let observations = recorder.observations.load(Ordering::Acquire);
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_no_held_dial(&upstream).await;
        if credential == Some(HeldForwardCredential::Revoked) {
            credentials.as_ref().unwrap().revoke_static_provider_environment(2);
        }
        recorder.decision.store(1, Ordering::Release);
        // Wake observation without relying on wall-clock polling latency.
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data.replace("path: /allowed", "path: /missing")).unwrap();
        let server = async {
            let (mut fresh, _) = tokio::select! {
                accepted = upstream.accept() => accepted.unwrap(),
                _ = proxy_listener.accept() => panic!("FORWARD must retain native direct routing"),
            };
            if credential.is_some_and(|kind| kind != HeldForwardCredential::Valid) {
                assert!(read_held_close(&mut fresh, false).await.is_empty(),
                    "unresolved application credentials must not release upstream bytes");
            } else {
                let authorization = if credential.is_some() {
                    "Bearer held-fixture-token"
                } else {
                    "header-sentinel"
                };
                serve_held_once_with_credentials(
                    &mut fresh,
                    destination,
                    false,
                    authorization,
                    credential.map(|_| "held-fixture-token"),
                ).await;
            }
        };
        let client = async {
            let response = read_held_close(&mut wire, false).await;
            if credential.is_some_and(|kind| kind != HeldForwardCredential::Valid) {
                let (status, error) = if credential == Some(HeldForwardCredential::EndpointMismatch) {
                    ("HTTP/1.1 403 Forbidden\r\n", "credential_endpoint_mismatch")
                } else {
                    ("HTTP/1.1 500 Internal Server Error\r\n", "credential_unavailable")
                };
                assert!(response.starts_with(status.as_bytes()),
                    "credential refusal must fail closed through the native relay");
                let body = response.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4;
                let body: serde_json::Value = serde_json::from_slice(&response[body..]).unwrap();
                assert_eq!(body["error"], error);
                assert!(!String::from_utf8_lossy(&response).contains("held-fixture-token"));
                assert!(!String::from_utf8_lossy(&response).contains("API_KEY"));
            } else {
                assert_eq!(response, HELD_RESPONSE);
            }
        };
        let (result, (), ()) = tokio::join!(handler, server, client);
        result.unwrap();
        assert_no_held_dial(&upstream).await;
        assert_eq!(proxy_listener.into_std().unwrap().accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock, "FORWARD must not dial the corporate CONNECT proxy");
        assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    })
    .await
    .expect("production FORWARD must resume once only after approval and coverage");
}

pub(super) fn held_test_identity() -> ContractBinaryIdentity {
    // Supplied by this trusted test fixture, NOT sampled from a live process.
    ContractBinaryIdentity {
        executable: ContractExecutableIdentity {
            path: executable_path("/usr/bin/curl"),
            digest: Some("44".repeat(32).parse().unwrap()),
        },
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    }
}

fn held_test_engine(destination: SocketAddr) -> (Arc<OpaEngine>, Arc<HeldIntentRecorder>, String) {
    let ip = destination.ip();
    let data = policy_with_native_executable_paths(&format!(
        "network_policies:\n  fixture:\n    endpoints:\n      - host: \"{ip}\"\n        port: {port}\n        protocol: rest\n        enforcement: enforce\n        allowed_ips: [\"{ip}/32\"]\n        rules:\n          - allow: {{method: GET, path: /allowed}}\n    binaries:\n      - path: /usr/bin/curl\n",
        port = destination.port(),
    ));
    let engine = Arc::new(
        native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data).unwrap(),
    );
    engine.attach_http_hitl_policy_observer();
    let recorder = Arc::new(HeldIntentRecorder::default());
    engine.set_http_hitl_proposal_service(recorder.clone());
    (engine, recorder, data)
}

async fn held_test_handler(
    client: tokio::io::DuplexStream,
    engine: Arc<OpaEngine>,
    tls: Option<Arc<ProxyTlsState>>,
) -> Result<()> {
    Box::pin(handle_mediated_connection(
        tokio::io::BufReader::new(Box::new(client)),
        Some(Ok(held_test_identity())),
        None,
        None,
        None,
        engine,
        Arc::new(BinaryIdentityCache::new()),
        Arc::new(AtomicU32::new(0)),
        tls,
        Some(held_proposal_context()),
        AgentProposals::default(),
        Arc::new(None),
        Arc::new(None),
        Arc::new(None),
        None,
        None,
        None,
        None,
        None,
        None,
    ))
    .await
}

#[derive(Clone, Copy, Debug)]
enum HeldForwardEnd {
    Rejected,
    Timeout,
    Unavailable,
    UnavailableThroughDeadline,
    Disabled,
    DefaultOff,
    ClientClosed,
}

impl HeldForwardEnd {
    fn expected_reason(self) -> Option<WaitEnd> {
        match self {
            Self::Rejected => Some(WaitEnd::ProposalRejected),
            Self::Timeout => Some(WaitEnd::Deadline),
            Self::Unavailable | Self::UnavailableThroughDeadline => {
                Some(WaitEnd::ProposalUnavailable)
            }
            Self::Disabled => Some(WaitEnd::Disabled),
            Self::ClientClosed => Some(WaitEnd::ClientClosed),
            Self::DefaultOff => None,
        }
    }

    fn decision(self) -> u32 {
        match self {
            Self::Rejected => 2,
            Self::Timeout => 0,
            Self::Unavailable => 3,
            Self::UnavailableThroughDeadline => 4,
            Self::Disabled | Self::ClientClosed => 1,
            Self::DefaultOff => unreachable!(),
        }
    }

    fn assert_response(self, response: &[u8]) {
        match self {
            Self::Rejected => assert_held_terminal_response(
                response,
                403,
                "approval_rejected",
                "approval_rejected",
            ),
            Self::Timeout => {
                assert_held_terminal_response(
                    response,
                    504,
                    "approval_timeout",
                    "approval_timeout",
                );
            }
            Self::Unavailable | Self::UnavailableThroughDeadline => assert_held_terminal_response(
                response,
                503,
                "approval_unavailable",
                "approval_unavailable",
            ),
            Self::Disabled => assert_held_terminal_response(
                response,
                503,
                "approval_unavailable",
                "approval_disabled",
            ),
            Self::ClientClosed => assert!(
                response.is_empty(),
                "closed client must not receive a response"
            ),
            Self::DefaultOff => unreachable!(),
        }
    }

    fn configure_deadline(self, engine: &OpaEngine) {
        if matches!(self, Self::Timeout | Self::UnavailableThroughDeadline) {
            engine.set_http_hitl_wait_limits(std::time::Duration::from_secs(1), 16, 4);
        }
    }
}

async fn held_forward_terminal_case(end: HeldForwardEnd) {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping FORWARD terminal fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), Box::pin(async {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let (engine, recorder, data) = held_test_engine(destination);
        end.configure_deadline(&engine);
        if !matches!(end, HeldForwardEnd::DefaultOff) {
            engine.set_http_hitl_wait_enabled(true);
        }
        let (client, mut wire) = tokio::io::duplex(8192);
        wire.write_all(format!(
            "GET http://{destination}/missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n"
        ).as_bytes()).await.unwrap();
        let handler = held_test_handler(client, engine.clone(), None);
        tokio::pin!(handler);
        if !matches!(end, HeldForwardEnd::DefaultOff) {
            drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > 0).await;
            assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
            assert_no_held_dial(&listener).await;
            recorder.decision.store(end.decision(), Ordering::Release);
            match end {
                HeldForwardEnd::Rejected | HeldForwardEnd::Timeout | HeldForwardEnd::Unavailable | HeldForwardEnd::UnavailableThroughDeadline => {}
                HeldForwardEnd::Disabled => {
                    engine.set_http_hitl_wait_enabled(false);
                }
                HeldForwardEnd::ClientClosed => {
                    wire.shutdown().await.unwrap();
                }
                HeldForwardEnd::DefaultOff => unreachable!(),
            }
            // Even installed coverage must not revive rejection, cancellation
            // or a disabled wait epoch.
            engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data.replace("path: /allowed", "path: /missing")).unwrap();
        }
        let client = async { read_held_close(&mut wire, false).await };
        let (result, response) = tokio::join!(handler, client);
        if let Some(expected_reason) = end.expected_reason() {
            // A held terminal is an explicit error, unlike the ordinary
            // default-off denial. Do not accept unrelated handler failures.
            let error = result.expect_err("terminal hold must not complete as a resumed request");
            assert_eq!(
                error.to_string(),
                format!(
                    "held review ended before fresh admission: reason={} ({expected_reason:?})",
                    expected_reason.reason_code()
                ),
                "wrong terminal result for {end:?}"
            );
        } else {
            result.unwrap();
        }
        // The handler has retired. Inspect the kernel backlog, not a possibly
        // stale Tokio readiness cache, to prove no connection was attempted.
        let listener = listener.into_std().unwrap();
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        if matches!(end, HeldForwardEnd::DefaultOff) {
            assert!(response.starts_with(b"HTTP/1.1 403"));
            assert!(recorder.metadata.lock().unwrap().is_empty());
            assert_eq!(recorder.observations.load(Ordering::Acquire), 0);
        } else {
            end.assert_response(&response);
            assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
        }
    })).await.unwrap_or_else(|_| panic!("FORWARD terminal case timed out: {end:?}"));
}

#[tokio::test]
async fn forward_production_ingress_rejected_never_dials() {
    held_forward_terminal_case(HeldForwardEnd::Rejected).await;
}

#[tokio::test]
async fn forward_production_ingress_timeout_returns_504_without_dialing() {
    held_forward_terminal_case(HeldForwardEnd::Timeout).await;
}

#[tokio::test]
async fn forward_production_ingress_unavailable_returns_503_without_dialing() {
    held_forward_terminal_case(HeldForwardEnd::Unavailable).await;
}

#[tokio::test]
async fn forward_production_ingress_gateway_down_through_deadline_returns_503() {
    held_forward_terminal_case(HeldForwardEnd::UnavailableThroughDeadline).await;
}

#[tokio::test]
async fn forward_production_ingress_disabled_epoch_never_dials() {
    held_forward_terminal_case(HeldForwardEnd::Disabled).await;
}

#[tokio::test]
async fn forward_production_ingress_default_off_denies_without_waiting() {
    held_forward_terminal_case(HeldForwardEnd::DefaultOff).await;
}

#[tokio::test]
async fn forward_production_ingress_client_closed_before_approval_never_dials() {
    held_forward_terminal_case(HeldForwardEnd::ClientClosed).await;
}

#[derive(Clone, Copy, Debug)]
enum HeldTlsEnd {
    Response,
    StaleBeforeWrite,
    ClientClosedBeforeWrite,
    SimulatedRejectedBeforeReadmission,
    SimulatedTimeoutBeforeReadmission,
    SimulatedUnavailableBeforeReadmission,
    SimulatedUnavailableThroughDeadline,
}

impl HeldTlsEnd {
    fn terminal(self) -> Option<HeldForwardEnd> {
        match self {
            Self::SimulatedRejectedBeforeReadmission => Some(HeldForwardEnd::Rejected),
            Self::SimulatedTimeoutBeforeReadmission => Some(HeldForwardEnd::Timeout),
            Self::SimulatedUnavailableBeforeReadmission => Some(HeldForwardEnd::Unavailable),
            Self::SimulatedUnavailableThroughDeadline => {
                Some(HeldForwardEnd::UnavailableThroughDeadline)
            }
            _ => None,
        }
    }
}

async fn held_tls_ingress_case(
    original_version: &'static rustls::SupportedProtocolVersion,
    upstream_version: &'static rustls::SupportedProtocolVersion,
    end: HeldTlsEnd,
) {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping CONNECT TLS fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(15), Box::pin(async {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let (engine, recorder, data) = held_test_engine(destination);
        engine.set_http_hitl_wait_enabled(true);
        if let Some(end) = end.terminal() { end.configure_deadline(&engine); }
        let ca = crate::l7::tls::SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let original_config = openshell_crypto::tls::client_builder_with_protocol_versions(&[original_version])
            .with_root_certificates(roots.clone()).with_no_client_auth();
        let upstream_config = openshell_crypto::tls::client_builder_with_protocol_versions(&[upstream_version])
            .with_root_certificates(roots).with_no_client_auth();
        // Both real TLS peers use this same fixture CA/ProxyTlsState. There is
        // no certificate-verification bypass or pre-created plaintext pair.
        let state = Arc::new(ProxyTlsState::new(crate::l7::tls::CertCache::new(ca), Arc::new(upstream_config)));
        let (client, mut wire) = tokio::io::duplex(64 * 1024);
        wire.write_all(format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes()).await.unwrap();
        let handler = held_test_handler(client, engine.clone(), Some(state.clone()));
        tokio::pin!(handler);
        let (old, _) = tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            result = handler.as_mut() => panic!("TLS ingress exited before old accept: {result:?}"),
        };
        let connect_response = async {
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                response.push(wire.read_u8().await.unwrap());
                assert!(response.len() < 1024);
            }
            assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        };
        tokio::select! {
            () = connect_response => {},
            result = handler.as_mut() => panic!("TLS ingress exited before CONNECT response: {result:?}"),
        }
        let hostname = ip.to_string();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(original_config));
        let handshakes = async {
            tokio::join!(
                connector.connect(rustls::pki_types::ServerName::try_from(hostname.clone()).unwrap(), wire),
                crate::l7::tls::tls_terminate_client(old, &state, &hostname),
            )
        };
        let (wire, old) = tokio::select! {
            pair = handshakes => pair,
            result = handler.as_mut() => panic!("TLS ingress exited during handshakes: {result:?}"),
        };
        let mut wire = wire.unwrap();
        let mut old = old.unwrap();
        assert_eq!(wire.get_ref().1.protocol_version(), Some(original_version.version));
        wire.write_all(format!("GET /a/../missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n").as_bytes()).await.unwrap();
        wire.flush().await.unwrap();
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > 0).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        let retired = tokio::select! {
            bytes = read_held_close(&mut old, true) => bytes,
            result = handler.as_mut() => panic!("TLS ingress exited while Pending: {result:?}"),
        };
        assert!(retired.is_empty(), "retired upstream must see zero HTTP bytes");
        assert_no_held_dial(&listener).await;
        let observations = recorder.observations.load(Ordering::Acquire);
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data).unwrap();
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_no_held_dial(&listener).await;
        let covered = data.replace("path: /allowed", "path: /missing");
        let observations = recorder.observations.load(Ordering::Acquire);
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &covered).unwrap();
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_no_held_dial(&listener).await;
        if let Some(terminal) = end.terminal() {
            // BOTH original and retired-upstream handshakes have completed.
            // Installed coverage alone above still holds Q while the simulated
            // HeldProposalService says Pending. Rejection must now retire Q,
            // not dial a fresh peer even though coverage remains installed.
            assert_eq!(recorder.decision.load(Ordering::Acquire), 0);
            recorder.decision.store(terminal.decision(), Ordering::Release);
            engine.reload(include_str!("../../../data/sandbox-policy.rego"), &covered).unwrap();
            let client = async {
                terminal.assert_response(&read_held_close(&mut wire, true).await);
                assert_eq!(wire.get_ref().1.protocol_version(), Some(original_version.version));
            };
            let (result, ()) = tokio::join!(handler, client);
            result.unwrap();
            assert_eq!(listener.into_std().unwrap().accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
            assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
            return;
        }
        recorder.decision.store(1, Ordering::Release);
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &covered).unwrap();
        let (fresh, _) = tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            result = handler.as_mut() => panic!("TLS ingress exited before fresh accept: {result:?}"),
        };
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        match end {
            HeldTlsEnd::Response => {
                let server = async {
                    let mut fresh = crate::l7::tls::tls_terminate_client(fresh, &state, &hostname).await.unwrap();
                    serve_held_once(&mut fresh, destination, true).await;
                };
                let client = async {
                    // This is the ORIGINAL TLS client object: no replacement
                    // handshake after either unrelated or covering reload.
                    assert_eq!(read_held_close(&mut wire, true).await, HELD_RESPONSE);
                    assert_eq!(wire.get_ref().1.protocol_version(), Some(original_version.version));
                };
                let (result, (), ()) = tokio::join!(handler, server, client);
                result.unwrap();
            }
            HeldTlsEnd::StaleBeforeWrite | HeldTlsEnd::ClientClosedBeforeWrite => {
                // Deliberately do not poll the fresh server handshake yet.
                // Readmission is blocked in TLS establishment, before any
                // application write. Cancel or stale its generation there.
                assert!(poll!(handler.as_mut()).is_pending());
                if matches!(end, HeldTlsEnd::StaleBeforeWrite) {
                    engine.reload(include_str!("../../../data/sandbox-policy.rego"), &covered).unwrap();
                } else {
                    wire.shutdown().await.unwrap();
                }
                let server = async {
                    assert!(crate::l7::tls::tls_terminate_client(fresh, &state, &hostname).await.is_err(),
                        "prewrite cancellation must abort fresh TLS, not send HTTP");
                };
                let client = async {
                    assert!(read_held_close(&mut wire, true).await.is_empty());
                };
                let (result, (), ()) = tokio::join!(handler, server, client);
                result.unwrap();
            }
            HeldTlsEnd::SimulatedRejectedBeforeReadmission | HeldTlsEnd::SimulatedTimeoutBeforeReadmission |
            HeldTlsEnd::SimulatedUnavailableBeforeReadmission | HeldTlsEnd::SimulatedUnavailableThroughDeadline =>
                unreachable!("review terminal retires before fresh dial"),
        }
        assert_no_held_dial(&listener).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
    })).await.unwrap_or_else(|_| panic!("TLS ingress timed out: {end:?}, original={:?}, upstream={:?}", original_version.version, upstream_version.version));
}

#[tokio::test]
async fn connect_production_ingress_original_tls_survives_reload_fresh_upstream_tls_four_grid() {
    for original in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for upstream in [&rustls::version::TLS12, &rustls::version::TLS13] {
            held_tls_ingress_case(original, upstream, HeldTlsEnd::Response).await;
        }
    }
}

#[tokio::test]
async fn connect_production_ingress_stale_before_fresh_tls_write_aborts() {
    held_tls_ingress_case(
        &rustls::version::TLS13,
        &rustls::version::TLS13,
        HeldTlsEnd::StaleBeforeWrite,
    )
    .await;
}

#[tokio::test]
async fn connect_production_ingress_client_cancel_before_fresh_tls_write_aborts() {
    held_tls_ingress_case(
        &rustls::version::TLS13,
        &rustls::version::TLS13,
        HeldTlsEnd::ClientClosedBeforeWrite,
    )
    .await;
}

#[tokio::test]
async fn connect_production_ingress_simulated_rejection_after_covered_pending_tls_four_grid_never_dials()
 {
    for original in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for upstream in [&rustls::version::TLS12, &rustls::version::TLS13] {
            held_tls_ingress_case(
                original,
                upstream,
                HeldTlsEnd::SimulatedRejectedBeforeReadmission,
            )
            .await;
        }
    }
}

#[tokio::test]
async fn connect_original_tls_timeout_and_unavailable_return_local_responses() {
    for original in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for end in [
            HeldTlsEnd::SimulatedTimeoutBeforeReadmission,
            HeldTlsEnd::SimulatedUnavailableBeforeReadmission,
            HeldTlsEnd::SimulatedUnavailableThroughDeadline,
        ] {
            held_tls_ingress_case(original, &rustls::version::TLS13, end).await;
        }
    }
}
