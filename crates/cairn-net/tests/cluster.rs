//! The networked protocol over real TCP sockets (loopback) with wall-clock deadlines.
//! Nodes are tasks here; `cairn-sidecar`'s tests run them as separate OS processes.

use cairn_net::cluster::LocalCluster;
use cairn_net::{
    Coordinator, FaultMode, NetError, NetFaultKind, NetPolicy, NodeId, CHECKPOINT_DOMAIN,
};
use std::time::{Duration, Instant};
use threshold_mldsa::fips204;

const TIMEOUT: Duration = Duration::from_millis(400);

fn message(tag: &str) -> Vec<u8> {
    [CHECKPOINT_DOMAIN, tag.as_bytes()].concat()
}

fn reference(seed: &[u8; 32], msg: &[u8]) -> ([u8; fips204::SIGNATURE_BYTES], u32) {
    fips204::sign_reference(&fips204::keygen_internal(seed), msg)
}

fn signer(leaf: u8, signer: u8) -> NodeId {
    NodeId::Signer { leaf, signer }
}

async fn cluster(seed: u8, faults: &[(NodeId, FaultMode)]) -> (LocalCluster, Coordinator) {
    let cluster = LocalCluster::start(&[seed; 32], faults, TIMEOUT, Duration::ZERO)
        .await
        .unwrap();
    let policy = NetPolicy {
        round_timeout: TIMEOUT,
        record: true,
        reinstate_every: 0,
        ..NetPolicy::default()
    };
    let coordinator = Coordinator::new(
        cluster.group.clone(),
        cluster.peers.clone(),
        policy,
        cluster.identity(NodeId::Coordinator),
    );
    (cluster, coordinator)
}

#[tokio::test(flavor = "multi_thread")]
async fn healthy_cluster_reproduces_the_single_signer_signature() {
    let (_cluster, mut coordinator) = cluster(50, &[]).await;
    for tag in ["a", "b", "c"] {
        let msg = message(tag);
        let (signature, report) = coordinator.sign(&msg).await.unwrap();
        let (expect, rejections) = reference(&[50; 32], &msg);
        assert_eq!(signature, expect);
        assert_eq!((report.rejections, report.retries), (rejections, 0));
        assert_eq!((report.signers.len(), report.engines.len()), (9, 3));
        assert_eq!(report.p2p_bytes.len(), 9, "nine signers dealt sub-shares");
        // The coordinator never receives share material: only these reply kinds reach it.
        let allowed = [
            "Ready",
            "Dealt",
            "ShareCheck",
            "Installed",
            "Challenge",
            "Verdict",
            "Ack",
        ];
        assert!(
            report.received_kinds.iter().all(|k| allowed.contains(k)),
            "{:?}",
            report.received_kinds
        );
        assert!(fips204::verify_standard(
            &coordinator.group().pk,
            &msg,
            &signature
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_signer_costs_one_real_deadline_then_is_skipped() {
    let (_cluster, mut coordinator) = cluster(51, &[(signer(1, 1), FaultMode::Stall)]).await;
    let msg = message("stall");
    let start = Instant::now();
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert!(
        start.elapsed() >= TIMEOUT,
        "the deadline is wall-clock: {:?}",
        start.elapsed()
    );
    assert_eq!(signature, reference(&[51; 32], &msg).0);
    assert_eq!(
        report.retries, 0,
        "silence at prepare is absorbed without a retry"
    );
    assert_eq!(report.faults.len(), 1);
    assert_eq!(report.faults[0].culprit, Some(signer(1, 1)));
    assert_eq!(report.faults[0].kind, NetFaultKind::Timeout);
    assert!(!report.signers.contains(&signer(1, 1)) && report.signers.contains(&signer(1, 4)));

    // Excluded now: the next checkpoint does not contact it, so it cannot cost a deadline.
    let (_, report) = coordinator.sign(&message("stall-2")).await.unwrap();
    assert!(report.faults.is_empty());
    assert!(!report.coordinator_bytes.contains_key(&signer(1, 1)));
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_nodes_fail_fast_and_three_never_block() {
    let (mut cluster, mut coordinator) = cluster(52, &[]).await;
    for id in [signer(1, 2), signer(2, 2), signer(3, 3), NodeId::Root(2)] {
        cluster.kill(id);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let msg = message("offline");
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert_eq!(signature, reference(&[52; 32], &msg).0);
    assert_eq!(report.faults.len(), 4);
    assert!(report
        .faults
        .iter()
        .all(|f| matches!(f.kind, NetFaultKind::Unreachable | NetFaultKind::Refused(_))));
    assert_eq!(
        report.engines,
        vec![NodeId::Root(1), NodeId::Root(3), NodeId::Root(4)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_sub_shares_name_their_signer() {
    let (_cluster, mut coordinator) = cluster(53, &[(signer(2, 2), FaultMode::BadShare)]).await;
    let msg = message("bad-share");
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert_eq!(signature, reference(&[53; 32], &msg).0);
    assert_eq!(report.retries, 1);
    assert_eq!(report.faults.len(), 1);
    assert_eq!(
        (report.faults[0].culprit, &report.faults[0].kind),
        (Some(signer(2, 2)), &NetFaultKind::BadShare)
    );
    assert!(coordinator.excluded().contains(&signer(2, 2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn deviating_root_engines_are_named_and_replaced_by_the_spare() {
    for (mode, kind) in [
        (FaultMode::WrongChallenge, NetFaultKind::Equivocation),
        (FaultMode::BadResponse, NetFaultKind::InconsistentResponse),
        (FaultMode::Stall, NetFaultKind::Timeout),
    ] {
        let (_cluster, mut coordinator) = cluster(54, &[(NodeId::Root(2), mode)]).await;
        let msg = message("root");
        let (signature, report) = coordinator.sign(&msg).await.unwrap();
        assert_eq!(signature, reference(&[54; 32], &msg).0, "{mode:?}");
        assert_eq!(report.faults.len(), 1, "{mode:?}: {:?}", report.faults);
        assert_eq!(
            (report.faults[0].culprit, &report.faults[0].kind),
            (Some(NodeId::Root(2)), &kind),
            "{mode:?}"
        );
        assert_eq!(
            report.engines,
            vec![NodeId::Root(1), NodeId::Root(3), NodeId::Root(4)],
            "{mode:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn losing_the_quorum_is_an_error_not_a_hang() {
    let stalled: Vec<_> = [(1, 1), (1, 2), (2, 1), (2, 2)]
        .map(|(l, s)| (signer(l, s), FaultMode::Stall))
        .to_vec();
    let (_cluster, mut coordinator) = cluster(55, &stalled).await;
    let err = coordinator.sign(&message("quorum")).await.err().unwrap();
    assert!(
        matches!(err, NetError::QuorumLost("leaf committees", ref f) if f.len() == 4),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nodes_refuse_messages_that_are_not_checkpoints() {
    let (_cluster, mut coordinator) = cluster(56, &[]).await;
    let err = coordinator.sign(b"transfer all funds").await.err().unwrap();
    assert!(matches!(err, NetError::QuorumLost(..)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn injected_latency_is_paid_on_the_wall_clock() {
    let cluster = LocalCluster::start(
        &[57; 32],
        &[],
        Duration::from_secs(2),
        Duration::from_millis(10),
    )
    .await
    .unwrap();
    let policy = NetPolicy {
        link_delay: Duration::from_millis(10),
        ..NetPolicy::default()
    };
    let mut coordinator = Coordinator::new(
        cluster.group.clone(),
        cluster.peers.clone(),
        policy,
        cluster.identity(NodeId::Coordinator),
    );
    let msg = message("wan");
    let start = Instant::now();
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert_eq!(signature, reference(&[57; 32], &msg).0);
    // Four setup exchanges and two per attempt, each a 20 ms round trip; the deal nests one more.
    let floor = Duration::from_millis(20) * (5 + 2 * (report.rejections + 1));
    assert!(
        start.elapsed() >= floor,
        "{:?} < {floor:?}",
        start.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn links_are_mutually_authenticated() {
    use cairn_net::transport::call;
    use cairn_net::{Body, CallError, ClusterTls, Frame, Link};
    let (cluster, _) = cluster(58, &[]).await;
    let target = signer(1, 1);
    let addr = cluster.peers[&target].clone();
    let prepare = |from: NodeId, to: NodeId| Frame {
        version: 2,
        from,
        to,
        session: [7; 32],
        body: Body::Prepare {
            message: message("tls"),
        },
    };
    let link = |tls| Link {
        timeout: TIMEOUT,
        delay: Duration::ZERO,
        tls,
    };

    // The coordinator's certificate is accepted.
    let ok = call(
        &addr,
        &link(cluster.identity(NodeId::Coordinator)),
        &prepare(NodeId::Coordinator, target),
    )
    .await;
    assert!(matches!(ok.map(|x| x.reply.body), Ok(Body::Ready { .. })));

    // A real node's certificate, but a frame claiming to come from the coordinator: no answer.
    let forged = call(
        &addr,
        &link(cluster.identity(signer(2, 2))),
        &prepare(NodeId::Coordinator, target),
    )
    .await;
    assert!(
        matches!(forged, Err(CallError::Protocol(_))),
        "forged sender must get nothing"
    );

    // A certificate from another CA (same names): the handshake or the first read fails.
    let other = ClusterTls::generate(&[NodeId::Coordinator, target]).unwrap();
    let outsider = std::sync::Arc::new(other.identity(NodeId::Coordinator).unwrap());
    let rejected = call(
        &addr,
        &link(outsider),
        &prepare(NodeId::Coordinator, target),
    )
    .await;
    assert!(
        matches!(rejected, Err(CallError::Protocol(_))),
        "an outsider must be rejected"
    );

    // Addressing leaf_1/signer_1 but reaching another node's port: the server name does not match.
    let wrong = cluster.peers[&signer(1, 2)].clone();
    let misrouted = call(
        &wrong,
        &link(cluster.identity(NodeId::Coordinator)),
        &prepare(NodeId::Coordinator, target),
    )
    .await;
    assert!(
        matches!(misrouted, Err(CallError::Protocol(e)) if e.contains("TLS")),
        "wrong server must fail the handshake"
    );
}
