// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn terminal_responses_have_fixed_status_reason_and_head_framing() {
    for (reason, status, error) in [
        (WaitEnd::ProposalRejected, 403, "approval_rejected"),
        (WaitEnd::Deadline, 504, "approval_timeout"),
        (WaitEnd::ProposalUnavailable, 503, "approval_unavailable"),
        (WaitEnd::Disabled, 503, "approval_unavailable"),
        (WaitEnd::Quarantined, 503, "approval_unavailable"),
        (WaitEnd::Shutdown, 503, "approval_unavailable"),
        (WaitEnd::PolicyChanged, 503, "approval_unavailable"),
        (
            WaitEnd::CurrentExecutorUnavailable,
            503,
            "approval_unavailable",
        ),
    ] {
        let response = terminal_response(reason, false).unwrap();
        let boundary = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let header = std::str::from_utf8(&response[..boundary]).unwrap();
        assert!(header.starts_with(&format!("HTTP/1.1 {status} ")));
        assert!(header.contains("Connection: close\r\n"));
        assert!(header.contains(&format!(
            "Content-Length: {}\r\n",
            response.len() - boundary
        )));
        let body: serde_json::Value = serde_json::from_slice(&response[boundary..]).unwrap();
        assert_eq!(body["error"], error);
        assert_eq!(body["reason"], reason.reason_code());
        assert_eq!(body["detail"], "HTTP request was not sent upstream");
        assert!(response.len() < 1024);
        assert_eq!(
            terminal_response(reason, true).unwrap(),
            response[..boundary]
        );
    }
    for reason in [
        WaitEnd::ClientClosed,
        WaitEnd::ClientError,
        WaitEnd::ExtraInput,
    ] {
        assert!(terminal_response(reason, false).is_none());
    }
}

#[derive(Default)]
struct BlockedTransport {
    writer: Writer,
    block_flush: bool,
    block_shutdown: bool,
}

impl AsyncRead for BlockedTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for BlockedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.block_flush {
            Poll::Pending
        } else {
            Pin::new(&mut self.writer).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.block_shutdown {
            Poll::Pending
        } else {
            Pin::new(&mut self.writer).poll_shutdown(cx)
        }
    }
}

#[tokio::test(start_paused = true)]
async fn terminal_write_flush_and_shutdown_share_one_bounded_budget() {
    for stage in 0..3 {
        let fixture = Fixture::new(Instant::now());
        let mut client = BlockedTransport {
            writer: Writer {
                ready: (stage != 0).then_some(usize::MAX),
                ..Writer::default()
            },
            block_flush: stage == 1,
            block_shutdown: stage == 2,
        };
        let start = Instant::now();
        let error =
            send_terminal_response(&mut client, &fixture.lifetime, WaitEnd::Deadline, false)
                .await
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(Instant::now() - start, TERMINAL_RESPONSE_TIMEOUT);
        assert!(
            !fixture.lifetime.has_started(),
            "local response is not an upstream write"
        );
        assert_eq!(
            fixture.runtime.population(),
            1,
            "response must not return quota early"
        );
        if stage == 0 {
            assert!(client.writer.bytes.is_empty());
        } else {
            assert_eq!(
                client.writer.bytes,
                terminal_response(WaitEnd::Deadline, false).unwrap()
            );
        }
        drop(client);
        let runtime = fixture.runtime.clone();
        drop(fixture);
        assert_eq!(runtime.population(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn terminal_response_cancellation_leaves_no_detached_writer() {
    let fixture = Fixture::new(Instant::now());
    let mut client = BlockedTransport::default();
    {
        let response = send_terminal_response(
            &mut client,
            &fixture.lifetime,
            WaitEnd::ProposalRejected,
            false,
        );
        tokio::pin!(response);
        assert!(futures::poll!(response.as_mut()).is_pending());
    }
    let polls = client.writer.write_polls;
    tokio::time::advance(TERMINAL_RESPONSE_TIMEOUT).await;
    assert_eq!(client.writer.write_polls, polls);
    assert!(client.writer.bytes.is_empty());
    assert!(!fixture.lifetime.has_started());
    assert_eq!(fixture.runtime.population(), 1);
}

#[tokio::test]
async fn terminal_response_never_writes_after_upstream_started() {
    let fixture = Fixture::new(Instant::now());
    fixture.lifetime.mark_started();
    let (mut client, mut wire) = tokio::io::duplex(8192);
    send_terminal_response(
        &mut client,
        &fixture.lifetime,
        WaitEnd::ProposalRejected,
        false,
    )
    .await
    .unwrap();
    drop(client);
    let mut bytes = Vec::new();
    wire.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn terminal_response_detects_closed_client_and_extra_input_before_writing() {
    for extra_input in [false, true] {
        let fixture = Fixture::new(Instant::now());
        let (mut client, mut wire) = tokio::io::duplex(8192);
        if extra_input {
            wire.write_all(b"pipeline-sentinel").await.unwrap();
        } else {
            wire.shutdown().await.unwrap();
        }
        send_terminal_response(
            &mut client,
            &fixture.lifetime,
            WaitEnd::ProposalRejected,
            false,
        )
        .await
        .unwrap();
        drop(client);
        let mut bytes = Vec::new();
        wire.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        assert!(!fixture.lifetime.has_started());
    }
}
