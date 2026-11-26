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
    // The refusal comes back in the nodes' own words, not as a lost quorum.
    assert!(
        matches!(err, NetError::Policy(ref reason) if reason.contains("not a checkpoint")),
        "{err}"
    );
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
        version: cairn_net::wire::NET_VERSION,
        from,
        to,
        session: [7; 32],
        body: Body::Prepare {
            message: message("tls"),
        },
    };
    let link = |tls| Link::new(TIMEOUT, Duration::ZERO, tls);

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

    // A certificate that is not pinned (same names): the handshake or the first read fails.
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

#[tokio::test(flavor = "multi_thread")]
async fn a_signer_deals_only_for_the_message_it_approved() {
    use cairn_net::transport::call;
    use cairn_net::{Body, Frame, Link};
    use threshold_mldsa::Active;
    let (cluster, _) = cluster(59, &[]).await;
    let target = signer(1, 1);
    let link = Link::new(
        TIMEOUT,
        Duration::ZERO,
        cluster.identity(NodeId::Coordinator),
    );
    let ask = |to: NodeId, session: [u8; 32], body: Body| {
        let (addr, link) = (cluster.peers[&to].clone(), link.clone());
        async move {
            let frame = Frame {
                version: cairn_net::wire::NET_VERSION,
                from: NodeId::Coordinator,
                to,
                session,
                body,
            };
            call(&addr, &link, &frame).await.unwrap().reply.body
        }
    };
    let leaves = (1..=3u8)
        .map(|leaf| {
            let members = (1..=3u8).map(|s| (s, Active::Signer)).collect();
            (leaf, Active::Committee(members))
        })
        .collect();
    let deal = Body::Deal {
        active: Active::Committee(leaves),
        roots: vec![1, 2, 3],
    };

    // No approval, no share: a coordinator cannot skip the signer's policy.
    let reply = ask(target, [1; 32], deal.clone()).await;
    assert!(
        matches!(&reply, Body::Refused { reason } if reason.contains("no approved message")),
        "{}",
        reply.kind()
    );

    // The signer approves one message and the engines are told another: the engines refuse
    // the signer's share, so nothing is signed that the signer did not agree to.
    let session = [2; 32];
    let prepare = |tag: &str| Body::Prepare {
        message: message(tag),
    };
    let ready = ask(target, session, prepare("approved")).await;
    assert!(matches!(ready, Body::Ready { .. }));
    for root in 1..=3 {
        let ready = ask(NodeId::Root(root), session, prepare("substituted")).await;
        assert!(matches!(ready, Body::Ready { .. }));
    }
    let reply = ask(target, session, deal.clone()).await;
    assert!(matches!(reply, Body::DealFailed { .. }), "{}", reply.kind());

    // One approval deals once.
    let reply = ask(target, session, deal).await;
    assert!(matches!(reply, Body::Refused { .. }), "{}", reply.kind());
}

#[tokio::test(flavor = "multi_thread")]
async fn engines_mask_only_for_a_session_all_three_signed() {
    use cairn_net::transport::call;
    use cairn_net::{Body, Frame, Link};
    use threshold_mldsa::Active;
    let (cluster, _) = cluster(60, &[]).await;
    let link = Link::new(
        TIMEOUT,
        Duration::ZERO,
        cluster.identity(NodeId::Coordinator),
    );
    let session = [3; 32];
    let ask = |to: NodeId, body: Body| {
        let (addr, link) = (cluster.peers[&to].clone(), link.clone());
        async move {
            let frame = Frame {
                version: cairn_net::wire::NET_VERSION,
                from: NodeId::Coordinator,
                to,
                session,
                body,
            };
            call(&addr, &link, &frame).await.unwrap().reply.body
        }
    };
    let leaves = (1..=3u8)
        .map(|leaf| {
            let members = (1..=3u8).map(|s| (s, Active::Signer)).collect();
            (leaf, Active::Committee(members))
        })
        .collect();
    let active = Active::Committee(leaves);
    let roots = vec![1u8, 2, 3];
    let signers: Vec<NodeId> = (1..=3)
        .flat_map(|l| (1..=3).map(move |s| signer(l, s)))
        .collect();
    let engines: Vec<NodeId> = roots.iter().map(|k| NodeId::Root(*k)).collect();

    // An honest run up to the point where the engines hold their shares.
    for id in signers.iter().chain(&engines) {
        let prepare = Body::Prepare {
            message: message("split"),
        };
        assert!(matches!(ask(*id, prepare).await, Body::Ready { .. }));
    }
    for id in &signers {
        let deal = Body::Deal {
            active: active.clone(),
            roots: roots.clone(),
        };
        assert!(matches!(ask(*id, deal).await, Body::Dealt { .. }));
    }
    let mut verification = Vec::new();
    for id in &engines {
        let collect = Body::Collect {
            active: active.clone(),
        };
        let Body::ShareCheck { values, missing } = ask(*id, collect).await else {
            panic!("no share check from {id}");
        };
        assert!(missing.is_empty());
        let mut sum = vec![0i64; values[0].1.len()];
        for (_, value) in &values {
            for (acc, v) in sum.iter_mut().zip(value) {
                *acc = (*acc + *v as i64).rem_euclid(fips204::Q as i64);
            }
        }
        verification.push(sum.into_iter().map(|v| v as i32).collect::<Vec<i32>>());
    }

    // The coordinator shows engine 3 another engine's verification share altered. Engine 3
    // can only check its own entry, so it installs; but it signs what it saw.
    let mut altered = verification.clone();
    altered[0][0] = (altered[0][0] + 1) % fips204::Q;
    let mut attestations = Vec::new();
    for (i, id) in engines.iter().enumerate() {
        let install = Body::Install {
            slot: i as u8 + 1,
            roots: roots.clone(),
            verification: if i == 2 {
                altered.clone()
            } else {
                verification.clone()
            },
        };
        let Body::Installed { attestation } = ask(*id, install).await else {
            panic!("{id} did not install");
        };
        attestations.push((roots[i], attestation));
    }

    // No engine runs the mask phase: 1 and 2 lack 3's signature on their session, 3 lacks
    // theirs, and none starts without the signatures at all.
    for id in &engines {
        for shown in [attestations.clone(), Vec::new()] {
            let mask = Body::Mask {
                attempt: 0,
                attestations: shown,
            };
            let reply = ask(*id, mask).await;
            assert!(
                matches!(&reply, Body::Refused { reason } if reason.contains("did not sign")),
                "{id}: {}",
                reply.kind()
            );
        }
    }
}
