// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures::poll;
use tokio::time::advance;

fn snapshot(status: &str) -> GetDraftPolicyResponse {
    GetDraftPolicyResponse {
        chunks: vec![PolicyChunk {
            id: "held".into(),
            status: status.into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[tokio::test(start_paused = true)]
async fn http_hitl_cleared_draft_is_resubmitted_and_observed() {
    let (_workspace, service) = service();
    let ledger = Mutex::new(HashMap::<String, PolicyChunk>::new());
    let calls = AtomicUsize::new(0);
    let submit = || {
        service.submit_candidate("workspace-a", candidate("workspace-a", "/items"), |chunk| {
            let ledger = &ledger;
            let calls = &calls;
            async move {
                let attempt = calls.fetch_add(1, Ordering::SeqCst);
                // Model the gateway's durable submission-key lookup, not a
                // local accepted-ID cache. Deletion removes the key as well.
                let mut ledger = ledger.lock().await;
                let stored = ledger
                    .entry(chunk.id.clone())
                    .or_insert_with(|| PolicyChunk {
                        id: format!("durable-{attempt}"),
                        status: "pending".into(),
                        ..chunk
                    });
                Ok(accepted(&stored.id))
            }
        })
    };
    let observe = |id| {
        service.observe_candidate("workspace-a", id, || async {
            Ok(GetDraftPolicyResponse {
                chunks: ledger.lock().await.values().cloned().collect(),
                ..Default::default()
            })
        })
    };

    let deleted_id = submit().await.unwrap();
    let submission_key = ledger.lock().await.keys().next().unwrap().clone();
    assert_eq!(observe(&deleted_id).await, Ok(ReviewDecision::Pending));
    ledger
        .lock()
        .await
        .retain(|_, chunk| chunk.status != "pending");
    advance(ATTEMPT_INTERVAL).await;
    assert_eq!(observe(&deleted_id).await, Ok(ReviewDecision::Unknown));

    // The same service/session and unchanged candidate must consult persistence
    // again, even though its old accepted ID is no longer reviewable.
    let replacement_id = submit().await.unwrap();
    assert_ne!(replacement_id, deleted_id);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(submit().await.unwrap(), replacement_id);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    {
        let ledger = ledger.lock().await;
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[&submission_key].id, replacement_id);
    }
    advance(ATTEMPT_INTERVAL).await;
    assert_eq!(observe(&replacement_id).await, Ok(ReviewDecision::Pending));
    ledger.lock().await.get_mut(&submission_key).unwrap().status = "approved".into();
    advance(ATTEMPT_INTERVAL).await;
    assert_eq!(observe(&replacement_id).await, Ok(ReviewDecision::Approved));
}

#[tokio::test(start_paused = true)]
async fn http_hitl_review_batch_is_shared_and_refreshes_once_per_interval() {
    let (_workspace, service) = service();
    let calls = AtomicUsize::new(0);
    let observe = || {
        service.observe_candidate("workspace-a", "held", || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(snapshot("pending"))
        })
    };
    let (a, b, c) = tokio::join!(observe(), observe(), observe());
    assert_eq!(a, Ok(ReviewDecision::Pending));
    assert_eq!(b, a);
    assert_eq!(c, a);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    advance(ATTEMPT_INTERVAL).await;
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(snapshot("approved"))
            })
            .await,
        Ok(ReviewDecision::Approved)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        service
            .observe_candidate("workspace-a", "absent", || async {
                panic!("a missing ID does not cause a second fetch");
            })
            .await,
        Ok(ReviewDecision::Unknown)
    );
}

#[tokio::test(start_paused = true)]
async fn http_hitl_review_slow_batch_is_coalesced_after_completion() {
    let (_workspace, service) = service();
    let calls = AtomicUsize::new(0);
    let slow = service.observe_candidate("workspace-a", "held", || async {
        calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(snapshot("approved"))
    });
    let queued = service.observe_candidate("workspace-a", "held", || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(snapshot("rejected"))
    });
    let (a, b) = tokio::join!(slow, queued);
    assert_eq!(a, Ok(ReviewDecision::Approved));
    assert_eq!(b, a);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_review_failure_clears_old_approval_without_parsing_reason() {
    let (_workspace, service) = service();
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async { Ok(snapshot("approved")) })
            .await,
        Ok(ReviewDecision::Approved)
    );
    advance(ATTEMPT_INTERVAL).await;
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async {
                Err(ProposalSubmitError::Retryable)
            })
            .await,
        Err(ProposalSubmitError::Retryable)
    );
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async {
                panic!("failed batch is rate limited")
            })
            .await,
        Ok(ReviewDecision::Unknown)
    );
    advance(ATTEMPT_INTERVAL).await;
    let mut response = snapshot("rejected");
    response.chunks[0].rejection_reason =
        "approved; covered by active policy; secret-sentinel".into();
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async { Ok(response) })
            .await,
        Ok(ReviewDecision::Rejected)
    );
    assert_eq!(
        service.review.lock().await.snapshot.as_ref().unwrap().len(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn http_hitl_review_unknown_duplicate_and_oversized_snapshot_fail_closed() {
    let (_workspace, service) = service();
    for (response, expected) in [
        (snapshot("future-status"), Ok(ReviewDecision::Unknown)),
        (
            GetDraftPolicyResponse {
                chunks: vec![PolicyChunk::default()],
                ..Default::default()
            },
            Err(ProposalSubmitError::Unavailable),
        ),
        (
            GetDraftPolicyResponse {
                chunks: vec![snapshot("approved").chunks[0].clone(); 2],
                ..Default::default()
            },
            Err(ProposalSubmitError::Unavailable),
        ),
        (
            GetDraftPolicyResponse {
                chunks: vec![PolicyChunk::default(); REVIEW_CHUNKS + 1],
                ..Default::default()
            },
            Err(ProposalSubmitError::Unavailable),
        ),
    ] {
        assert_eq!(
            service
                .observe_candidate("workspace-a", "held", || async { Ok(response) })
                .await,
            expected
        );
        advance(ATTEMPT_INTERVAL).await;
    }
}

#[tokio::test(start_paused = true)]
async fn http_hitl_review_timeout_and_cancel_release_lock_without_detached_fetch() {
    let (_workspace, service) = service();
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", std::future::pending)
            .await,
        Err(ProposalSubmitError::Retryable)
    );
    advance(ATTEMPT_INTERVAL).await;
    {
        let observation = service.observe_candidate("workspace-a", "held", std::future::pending);
        tokio::pin!(observation);
        assert!(poll!(observation.as_mut()).is_pending());
    }
    assert!(service.review.try_lock().is_ok());
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async {
                panic!("cancelled read still consumes the rate limit")
            })
            .await,
        Ok(ReviewDecision::Unknown)
    );
    advance(ATTEMPT_INTERVAL).await;
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async { Ok(snapshot("pending")) })
            .await,
        Ok(ReviewDecision::Pending)
    );
}

#[tokio::test(start_paused = true)]
async fn http_hitl_review_workspace_is_checked_before_and_after_read_and_cache() {
    let (workspace, service) = service();
    assert_eq!(
        service
            .observe_candidate("other", "held", || async {
                panic!("wrong workspace must not fetch")
            })
            .await,
        Err(ProposalSubmitError::Unavailable)
    );
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async {
                workspace.send_replace("other".into());
                Ok(snapshot("approved"))
            })
            .await,
        Err(ProposalSubmitError::Unavailable)
    );
    assert!(service.review.lock().await.snapshot.is_none());
    workspace.send_replace("workspace-a".into());
    advance(ATTEMPT_INTERVAL).await;
    service
        .observe_candidate("workspace-a", "held", || async { Ok(snapshot("approved")) })
        .await
        .unwrap();
    workspace.send_replace("other".into());
    assert_eq!(
        service
            .observe_candidate("workspace-a", "held", || async {
                panic!("wrong workspace cannot read cached decisions")
            })
            .await,
        Err(ProposalSubmitError::Unavailable)
    );
}
