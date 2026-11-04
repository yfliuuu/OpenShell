// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Limited HITL MVP: captured trusted identity, fresh native admission, one
//! frozen REST exchange. Current-executor continuity is explicitly deferred.

use super::*;
use crate::l7::provider::L7Request;
use crate::l7::session::{HttpSession, ReviewWaitOutcome};
use crate::l7::wait::ResumeFence;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Trusted ingress mode, independent of request-target syntax and TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HeldProxyMode {
    Connect,
    Forward,
}

pub(super) struct ResumeEnvironment {
    pub engine: Arc<OpaEngine>,
    pub entrypoint_pid: Arc<AtomicU32>,
    pub backend_host_gateway: Arc<Option<IpAddr>>,
    pub trusted_host_gateway: Arc<Option<IpAddr>>,
    pub upstream_proxy: Arc<Option<UpstreamProxyConfig>>,
    pub tls_state: Option<Arc<ProxyTlsState>>,
    pub policy_local_ctx: Option<Arc<PolicyLocalContext>>,
    pub provider_credentials: Option<ProviderCredentialState>,
    pub secret_resolver: Option<Arc<SecretResolver>>,
    pub agent_proposals: openshell_core::proposals::AgentProposals,
    pub activity: Option<ActivitySender>,
    pub endpoint_observation: Option<EndpointObservationSender>,
}

impl ResumeEnvironment {
    fn check_workspace(&self, workspace: &str) -> Result<()> {
        if self
            .policy_local_ctx
            .as_ref()
            .is_none_or(|ctx| ctx.workspace() != workspace)
        {
            return Err(miette::miette!("held request workspace changed"));
        }
        Ok(())
    }
}

pub(super) async fn resume_after_review<C>(
    session: &mut HttpSession<C>,
    environment: &ResumeEnvironment,
    mode: HeldProxyMode,
    tls: bool,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    match session.wait_for_approval().await {
        Some(ReviewWaitOutcome::Covered { generation }) => {
            let result = resume_once(session, environment, mode, tls, generation).await;
            // At most one attempt, even if a connect, write, response or flush failed.
            // No persistent decision can reconstruct this transport or revive Q.
            session.parts().1.terminate();
            result
        }
        Some(ReviewWaitOutcome::Terminal(reason)) => Err(miette::miette!(
            "held review ended before fresh admission: reason={} ({reason:?})",
            reason.reason_code()
        )),
        None => Ok(()),
    }
}

/// Rewrite an outgoing copy; the ingress mode comes only from the caller,
/// never from a client-controlled target or the state of parser normalization.
fn prepare_outgoing_request(
    frozen: &L7Request,
    mode: HeldProxyMode,
    host: &str,
    port: u16,
) -> Result<L7Request> {
    let mut request = frozen.clone();
    let line = std::str::from_utf8(&request.raw_header)
        .into_diagnostic()?
        .split("\r\n")
        .next()
        .ok_or_else(|| miette::miette!("held request line unavailable"))?;
    let target = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| miette::miette!("held request target unavailable"))?;
    let (canonical, query) = crate::l7::path::canonicalize_request_target(
        target,
        &crate::l7::path::CanonicalizeOptions::default(),
    )
    .into_diagnostic()?;
    if canonical.path != request.target {
        return Err(miette::miette!("held request canonical projection changed"));
    }
    request.raw_header = match mode {
        HeldProxyMode::Connect => crate::l7::rest::rewrite_request_line_target(
            &request.raw_header,
            &request.action,
            &canonical.path,
            query.as_deref(),
            "HTTP/1.1",
        )?,
        HeldProxyMode::Forward => {
            // Reuse native FORWARD sanitization even if a parser already made
            // the target origin-form. Live credentials are prepared later,
            // only after fresh admission in relay_held_rest_once.
            let upstream_target = match query.as_deref() {
                Some(query) if !query.is_empty() => format!("{}?{query}", canonical.path),
                _ => canonical.path,
            };
            rewrite_forward_request(
                &request.raw_header,
                request.raw_header.len(),
                &upstream_target,
                &canonical_forward_authority(host, port),
                None,
            )
            .map_err(miette::Report::new)?
        }
    };
    Ok(request)
}

async fn resume_once<C>(
    session: &mut HttpSession<C>,
    environment: &ResumeEnvironment,
    mode: HeldProxyMode,
    tls: bool,
    generation: u64,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let slot = session.slot();
    let input = slot
        .held_input()
        .ok_or_else(|| miette::miette!("held intent unavailable"))?;
    let network = input
        .captured_network_input()
        .ok_or_else(|| miette::miette!("held scope unavailable"))?;
    let workspace = input.workspace().to_owned();
    environment.check_workspace(&workspace)?;
    let request = prepare_outgoing_request(
        slot.frozen()
            .ok_or_else(|| miette::miette!("held request unavailable"))?
            .request(),
        mode,
        &network.host,
        network.port,
    )?;
    let request_id = slot.review_request_id().unwrap_or_default().to_owned();
    let guard = slot
        .readmission_guard(generation)
        .map_err(|reason| miette::miette!("held admission ended: {reason:?}"))?;
    let fence = slot
        .resume_fence()
        .ok_or_else(|| miette::miette!("held lifetime unavailable"))?;

    // Re-authorize using the captured trusted executable/ancestor chain, not
    // argv, the old L4 decision, or the coverage bit. This is NOT a fresh
    // executor proof. Native TOFU was applied at original connection admission.
    let authorization = environment.engine.authorize_egress(&network)?;
    if authorization.generation != generation
        || !matches!(authorization.action, NetworkAction::Allow { .. })
    {
        return Err(miette::miette!(
            "held request no longer allowed by current policy"
        ));
    }
    let mut decision = EgressDecision {
        intent: match mode {
            HeldProxyMode::Connect => EgressIntent::connect(network.host.clone(), network.port),
            HeldProxyMode::Forward => {
                EgressIntent::forward_http(network.host.clone(), network.port)
            }
        },
        action: authorization.action.clone(),
        policy_generation: authorization.generation,
        identity: ProcessIdentityEvidence::Available,
        endpoint: EndpointDecision::from_authorization(&authorization),
        binary: Some(network.binary_path),
        binary_pid: None,
        ancestors: network.ancestors,
        cmdline_paths: Vec::new(),
    };
    hydrate_l7_route(&mut decision);
    hydrate_tls_mode(&mut decision);
    if decision.endpoint.tls_mode == crate::l7::TlsMode::Skip {
        return Err(miette::miette!(
            "held REST route cannot become an uninspected tunnel"
        ));
    }
    let route = decision
        .endpoint
        .l7_route
        .as_ref()
        .ok_or_else(|| miette::miette!("held REST route unavailable"))?;
    relay::validate_route_generation(Some(route), generation)?;
    let config = select_l7_config_for_path(&route.configs, &request.target)
        .ok_or_else(|| miette::miette!("held REST endpoint unavailable"))?
        .config
        .clone();
    let evaluator = relay::pin_l7_evaluator(&environment.engine, generation)?;
    let mut ctx = relay::http_context(
        &decision,
        environment.provider_credentials.clone(),
        environment.secret_resolver.clone(),
        environment.agent_proposals.clone(),
        workspace.clone(),
        relay::RelaySignals {
            activity: environment.activity.clone(),
            endpoint_observation: environment.endpoint_observation.clone(),
        },
    );
    ctx.request_default_port = Some(if tls { 443 } else { 80 });
    if config.protocol != crate::l7::L7Protocol::Rest
        || config.enforcement != crate::l7::EnforcementMode::Enforce
        || !crate::l7::relay::request_authority_matches_endpoint(&request, &ctx)
    {
        return Err(miette::miette!(
            "held request no longer has enforced REST authority"
        ));
    }
    let current = crate::l7::hitl::evaluate_l7_request_classified(
        &evaluator,
        &ctx,
        &crate::l7::L7RequestInfo {
            action: request.action.clone(),
            target: request.target.clone(),
            query_params: request.query_params.clone(),
            graphql: None,
            jsonrpc: None,
        },
    )?;
    if !current.allowed || !current.l4_allowed || !current.binary_identity_required {
        return Err(miette::miette!(
            "held request denied by current REST policy"
        ));
    }
    hydrate_destination_plan(
        &mut decision,
        *environment.backend_host_gateway,
        *environment.trusted_host_gateway,
    )
    .map_err(|_| miette::miette!("held destination configuration rejected"))?;
    let plan = decision
        .endpoint
        .destination
        .as_ref()
        .ok_or_else(|| miette::miette!("held destination plan unavailable"))?;
    guard.ensure_current()?;
    ocsf_emit!(NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other).severity(SeverityId::Informational)
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .unmapped("request_id", serde_json::json!(request_id))
        .unmapped("resumed_generation", serde_json::json!(generation))
        .message("HTTP_HITL_READMISSION captured-connection identity MVP; executor continuity deferred")
        .build());

    let (client, _) = session.parts();
    let (mut client_read, client_write) = tokio::io::split(client);
    let mut client = ResponseOnly(client_write);
    let operation = async {
        let connector = validate_destination(DestinationRequest {
            host: &ctx.host,
            port: ctx.port,
            sandbox_entrypoint_pid: environment.entrypoint_pid.load(Ordering::Acquire),
            plan,
        })
        .await
        .map_err(|_| miette::miette!("held destination validation failed"))?;
        guard.ensure_current()?;
        environment.check_workspace(&workspace)?;
        fence
            .check()
            .map_err(|reason| miette::miette!("held admission ended: {reason:?}"))?;
        // CONNECT keeps the native corporate proxy/NO_PROXY route even when
        // its application stream is plaintext. FORWARD retains native direct
        // dialing. TLS controls only the handshake, never routing or fallback.
        let upstream = match mode {
            HeldProxyMode::Connect => dial_upstream(
                &environment.upstream_proxy,
                &ctx.host,
                &ctx.host,
                ctx.port,
                connector.addrs(),
            )
            .await
            .into_diagnostic()?,
            HeldProxyMode::Forward => upstream_proxy::PrefixedStream::without_prefix(
                connector.connect().await.into_diagnostic()?,
            ),
        };
        let stream: Box<dyn openshell_isolation_interface::contract::DuplexStream + '_> = if tls {
            let state = environment
                .tls_state
                .as_ref()
                .ok_or_else(|| miette::miette!("upstream TLS unavailable"))?;
            Box::new(
                crate::l7::tls::tls_connect_upstream(upstream, &ctx.host, state.upstream_config())
                    .await?,
            )
        } else {
            Box::new(upstream)
        };
        guard.ensure_current()?;
        environment.check_workspace(&workspace)?;
        let mut upstream = ApplicationFence {
            inner: stream,
            policy: &guard,
            lifetime: &fence,
            environment,
            workspace: &workspace,
        };
        crate::l7::relay::relay_held_rest_once(
            request,
            &mut client,
            &mut upstream,
            &ctx,
            &evaluator,
            &config,
            &request_id,
        )
        .await
    };
    let mut extra = [0u8; 1];
    let result = tokio::select! {
        biased;
        () = guard.wait_until_stale() => Err(miette::miette!("policy changed during held exchange")),
        reason = fence.wait_cancelled() => Err(miette::miette!("held exchange ended: {reason:?}")),
        _ = client_read.read(&mut extra) => Err(miette::miette!("held client closed or sent additional input")),
        result = operation => result,
    };
    let outcome = match (fence.has_started(), result.is_ok()) {
        (true, true) => "response_observed",
        (true, false) => "effect_unknown",
        (false, _) => "not_sent",
    };
    ocsf_emit!(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .severity(SeverityId::Informational)
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .unmapped("request_id", serde_json::json!(request_id))
            .unmapped("outcome", serde_json::json!(outcome))
            .message("HTTP_HITL_EXCHANGE terminal; no retry or business-outcome inference")
            .build()
    );
    result
}

/// A bodyless frozen request never reads the client again. Its original read
/// half is independently monitored for EOF and pipeline input until close.
struct ResponseOnly<W>(W);
impl<W: Unpin> AsyncRead for ResponseOnly<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for ResponseOnly<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// This wrapper surrounds application writes AFTER the fresh TLS handshake.
/// Check again on each Pending re-poll. Only a positive HTTP write ends the
/// capture deadline; runtime and policy fences continue through the response.
struct ApplicationFence<'a, U> {
    inner: U,
    policy: &'a PolicyGenerationGuard,
    lifetime: &'a ResumeFence,
    environment: &'a ResumeEnvironment,
    workspace: &'a str,
}
impl<U> ApplicationFence<'_, U> {
    fn check(&self) -> io::Result<()> {
        self.policy
            .ensure_current()
            .map_err(|_| io::Error::other("held policy stale"))?;
        self.lifetime
            .check()
            .map_err(|_| io::Error::other("held lifetime ended"))?;
        self.environment
            .check_workspace(self.workspace)
            .map_err(|_| io::Error::other("held workspace changed"))
    }
}
impl<U: AsyncRead + Unpin> AsyncRead for ApplicationFence<'_, U> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<U: AsyncWrite + Unpin> AsyncWrite for ApplicationFence<'_, U> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.check() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.lifetime.mark_started();
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
