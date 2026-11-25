//! The three-round threshold protocol over real TLS sockets on loopback.

use cairn_net::transport::call;
use cairn_net::{
    Body, FaultMode, FlatCoordinator, Frame, Link, LocalCommittee, NetError, NetFaultKind,
    NetPolicy, NodeId, CHECKPOINT_DOMAIN,
};
use std::time::{Duration, Instant};
use threshold_mldsa::fips204;

const TIMEOUT: Duration = Duration::from_millis(1500);

fn message(tag: &str) -> Vec<u8> {
    [CHECKPOINT_DOMAIN, tag.as_bytes()].concat()
}

async fn committee(
    t: usize,
    n: usize,
    faults: &[(NodeId, FaultMode)],
) -> (LocalCommittee, FlatCoordinator) {
    let committee = LocalCommittee::start(t, n, faults, Duration::ZERO)
        .await
        .unwrap();
    let policy = NetPolicy {
        round_timeout: TIMEOUT,
        reinstate_every: 0,
        ..NetPolicy::default()
    };
    let coordinator = FlatCoordinator::new(
        committee.key.clone(),
        committee.peers.clone(),
        policy,
        committee.identity(NodeId::Coordinator),
    );
    (committee, coordinator)
}

#[tokio::test(flavor = "multi_thread")]
async fn committees_sign_standard_signatures_over_the_network() {
    for (t, n) in [(2, 3), (3, 4)] {
        let (_committee, mut coordinator) = committee(t, n, &[]).await;
        for tag in ["a", "b"] {
            let msg = message(tag);
            let (signature, report) = coordinator.sign(&msg).await.unwrap();
            assert!(
                fips204::verify_standard(&coordinator.key().pk, &msg, &signature),
                "{t}-of-{n}"
            );
            assert!(!fips204::verify_standard(
                &coordinator.key().pk,
                b"other",
                &signature
            ));
            assert_eq!(report.signers.len(), t);
            assert!(report.faults.is_empty() && report.retries == 0);
            // Per execution: reveal, respond, and the next execution's commitment, per party. The
            // very first execution also fetches its own commitments.
            let executions = report.rejections as u64 + 1;
            let first = if tag == "a" { t as u64 } else { 0 };
            assert_eq!(report.exchanges, 3 * t as u64 * executions + first);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_party_is_replaced_by_the_spare() {
    let (_committee, mut coordinator) =
        committee(3, 4, &[(NodeId::Party(2), FaultMode::Stall)]).await;
    let msg = message("stall");
    let start = Instant::now();
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert!(start.elapsed() >= TIMEOUT, "the deadline is wall-clock");
    assert!(fips204::verify_standard(
        &coordinator.key().pk,
        &msg,
        &signature
    ));
    assert_eq!(report.faults[0].culprit, Some(NodeId::Party(2)));
    assert_eq!(report.faults[0].kind, NetFaultKind::Timeout);
    assert_eq!(
        report.signers,
        vec![NodeId::Party(1), NodeId::Party(3), NodeId::Party(4)]
    );
    assert!(coordinator.excluded().contains(&NodeId::Party(2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_response_is_detected_and_rotated_away() {
    let (_committee, mut coordinator) =
        committee(3, 4, &[(NodeId::Party(1), FaultMode::BadResponse)]).await;
    let msg = message("bad");
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert!(fips204::verify_standard(
        &coordinator.key().pk,
        &msg,
        &signature
    ));
    assert!(report.retries >= 1);
    assert!(report
        .faults
        .iter()
        .all(|f| f.culprit.is_none() && matches!(f.kind, NetFaultKind::Unattributed(_))));
    assert!(
        !report.signers.contains(&NodeId::Party(1)),
        "{:?}",
        report.signers
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn too_few_parties_is_an_error_and_other_messages_are_refused() {
    let stalled = [
        (NodeId::Party(1), FaultMode::Stall),
        (NodeId::Party(2), FaultMode::Stall),
    ];
    let (_committee, mut coordinator) = committee(3, 4, &stalled).await;
    let err = coordinator.sign(&message("quorum")).await.err().unwrap();
    assert!(matches!(err, NetError::QuorumLost(..)), "{err}");

    let (_committee, mut coordinator) = committee(2, 3, &[]).await;
    assert!(coordinator.sign(b"transfer all funds").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_party_answers_a_session_once() {
    let (committee, _) = committee(2, 3, &[]).await;
    let link = Link::new(
        TIMEOUT,
        Duration::ZERO,
        committee.identity(NodeId::Coordinator),
    );
    let session = [9u8; 32];
    let ask = |to: u8, body: Body| {
        let frame = Frame {
            version: 2,
            from: NodeId::Coordinator,
            to: NodeId::Party(to),
            session,
            body,
        };
        let (addr, link) = (committee.peers[&NodeId::Party(to)].clone(), link.clone());
        async move { call(&addr, &link, &frame).await.unwrap().reply.body }
    };
    let mut commitments = Vec::new();
    let mut ids = std::collections::BTreeMap::new();
    for p in [1u8, 2] {
        let Body::PresignCommit { id, commitment } = ask(p, Body::Presign).await else {
            panic!()
        };
        commitments.push((p - 1, commitment));
        ids.insert(p, id);
    }
    let m2 = |p: u8| Body::M2 {
        message: message("once"),
        presign: ids[&p],
        commitments: commitments.clone(),
    };
    let mut revealed = Vec::new();
    for p in [1u8, 2] {
        let Body::M2Reveal { w } = ask(p, m2(p)).await else {
            panic!()
        };
        revealed.push((p - 1, w));
    }
    // The masks left the pool at the first reveal: a second reveal request gets nothing.
    assert!(matches!(ask(2, m2(2)).await, Body::Refused { .. }));
    let m3 = || Body::M3 {
        revealed: revealed.clone(),
    };
    // Each party answers its session once...
    assert!(matches!(ask(1, m3()).await, Body::M3Response { .. }));
    assert!(matches!(ask(2, m3()).await, Body::M3Response { .. }));
    // ...and then the masks are erased: the same challenge, or any other, gets nothing.
    assert!(matches!(ask(1, m3()).await, Body::Refused { .. }));
    assert!(matches!(ask(2, m3()).await, Body::Refused { .. }));
}
