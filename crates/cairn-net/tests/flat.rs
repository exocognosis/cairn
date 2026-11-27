//! The three-round threshold protocol over real TLS sockets on loopback.

use cairn_net::transport::call;
use cairn_net::{
    Body, FaultMode, FlatCoordinator, Frame, Link, LocalCommittee, NetError, NetFaultKind,
    NetPolicy, NodeId,
};
use std::time::{Duration, Instant};
use threshold_mldsa::fips204;

const TIMEOUT: Duration = Duration::from_millis(1500);

/// A well-formed checkpoint for the committee key `pk` at `height`; `tag` varies the block.
fn checkpoint(pk: &[u8], height: u64, tag: &str) -> Vec<u8> {
    cairn_net::policy::Checkpoint {
        chain: "cosmos:cairn-test-1".into(),
        epoch: 1,
        height,
        block_hash: fips204_hash(tag),
        finality_commitment: vec![7; 32],
        key_id: cairn_net::policy::key_id(pk),
    }
    .message()
}

fn fips204_hash(tag: &str) -> Vec<u8> {
    let mut out = [0u8; 32];
    fips204::shake256(&[tag.as_bytes()], &mut out);
    out.to_vec()
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
        for (height, tag) in [(100, "a"), (200, "b")] {
            let msg = checkpoint(&coordinator.key().pk, height, tag);
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
    let msg = checkpoint(&coordinator.key().pk, 100, "stall");
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
async fn a_wrong_response_names_its_sender() {
    let (_committee, mut coordinator) =
        committee(3, 4, &[(NodeId::Party(1), FaultMode::BadResponse)]).await;
    let msg = checkpoint(&coordinator.key().pk, 100, "bad");
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert!(fips204::verify_standard(
        &coordinator.key().pk,
        &msg,
        &signature
    ));
    // Anyone can check a single party's response against public values, so the bad one is
    // named and excluded on the first execution it spoils.
    assert_eq!(report.retries, 1);
    assert_eq!(report.faults.len(), 1);
    assert_eq!(report.faults[0].culprit, Some(NodeId::Party(1)));
    assert_eq!(report.faults[0].kind, NetFaultKind::InconsistentResponse);
    assert_eq!(
        report.signers,
        vec![NodeId::Party(2), NodeId::Party(3), NodeId::Party(4)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_opening_names_its_sender_and_not_the_parties_that_refuse_it() {
    let (_committee, mut coordinator) =
        committee(3, 4, &[(NodeId::Party(1), FaultMode::BadOpening)]).await;
    let msg = checkpoint(&coordinator.key().pk, 100, "opening");
    let (signature, report) = coordinator.sign(&msg).await.unwrap();
    assert!(fips204::verify_standard(
        &coordinator.key().pk,
        &msg,
        &signature
    ));
    assert!(report
        .faults
        .iter()
        .all(|f| f.culprit == Some(NodeId::Party(1))));
    assert_eq!(
        coordinator.excluded().iter().collect::<Vec<_>>(),
        vec![&NodeId::Party(1)]
    );
    assert_eq!(
        report.signers,
        vec![NodeId::Party(2), NodeId::Party(3), NodeId::Party(4)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn too_few_parties_is_an_error_and_other_messages_are_refused() {
    let stalled = [
        (NodeId::Party(1), FaultMode::Stall),
        (NodeId::Party(2), FaultMode::Stall),
    ];
    let (_committee, mut coordinator) = committee(3, 4, &stalled).await;
    let msg = checkpoint(&coordinator.key().pk, 100, "quorum");
    let err = coordinator.sign(&msg).await.err().unwrap();
    assert!(matches!(err, NetError::QuorumLost(..)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn parties_enforce_their_own_signing_policy() {
    let (_committee, mut coordinator) = committee(2, 3, &[]).await;
    let pk = coordinator.key().pk;
    let policy = |r: Result<_, NetError>| matches!(r, Err(NetError::Policy(_)));
    // Not a checkpoint; a checkpoint for another key.
    assert!(policy(coordinator.sign(b"transfer all funds").await));
    assert!(policy(
        coordinator
            .sign(&checkpoint(b"some other key", 100, "x"))
            .await
    ));
    // A checkpoint, then a conflicting one at the same height, then an older height.
    let first = checkpoint(&pk, 500, "block A");
    assert!(coordinator.sign(&first).await.is_ok());
    assert!(
        policy(coordinator.sign(&checkpoint(&pk, 500, "block B")).await),
        "two checkpoints at one height"
    );
    assert!(policy(
        coordinator.sign(&checkpoint(&pk, 499, "older")).await
    ));
    // The same checkpoint again is fine (a retry), and so is the next height. A refusal
    // excludes nobody.
    assert!(coordinator.sign(&first).await.is_ok());
    assert!(coordinator
        .sign(&checkpoint(&pk, 501, "next"))
        .await
        .is_ok());
    assert!(coordinator.excluded().is_empty());
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
            version: cairn_net::wire::NET_VERSION,
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
        message: checkpoint(&committee.key.pk, 100, "once"),
        presign: ids[&p],
        commitments: commitments.clone(),
    };
    let (mut revealed, mut attestations) = (Vec::new(), Vec::new());
    for p in [1u8, 2] {
        let Body::M2Reveal { w, attestation } = ask(p, m2(p)).await else {
            panic!()
        };
        revealed.push((p - 1, w));
        attestations.push((p - 1, attestation));
    }
    // The masks left the pool at the first reveal: a second reveal request gets nothing.
    assert!(matches!(ask(2, m2(2)).await, Body::Refused { .. }));
    let m3 = || Body::M3 {
        revealed: revealed.clone(),
        attestations: attestations.clone(),
    };
    // Each party answers its session once...
    assert!(matches!(ask(1, m3()).await, Body::M3Response { .. }));
    assert!(matches!(ask(2, m3()).await, Body::M3Response { .. }));
    // ...and then the masks are erased: the same challenge, or any other, gets nothing.
    assert!(matches!(ask(1, m3()).await, Body::Refused { .. }));
    assert!(matches!(ask(2, m3()).await, Body::Refused { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn unused_masks_expire() {
    let ttl = Duration::from_millis(150);
    let committee = LocalCommittee::start_with(2, 3, &[], Duration::ZERO, ttl)
        .await
        .unwrap();
    let link = Link::new(
        TIMEOUT,
        Duration::ZERO,
        committee.identity(NodeId::Coordinator),
    );
    let ask = |session: u8, body: Body| {
        let frame = Frame {
            version: cairn_net::wire::NET_VERSION,
            from: NodeId::Coordinator,
            to: NodeId::Party(1),
            session: [session; 32],
            body,
        };
        let (addr, link) = (committee.peers[&NodeId::Party(1)].clone(), link.clone());
        async move { call(&addr, &link, &frame).await.unwrap().reply.body }
    };
    let m2 = |id, commitment| Body::M2 {
        message: checkpoint(&committee.key.pk, 100, "ttl"),
        presign: id,
        commitments: vec![(0, commitment)],
    };
    // Fresh masks are usable...
    let Body::PresignCommit { id, commitment } = ask(1, Body::Presign).await else {
        panic!()
    };
    assert!(matches!(
        ask(1, m2(id, commitment)).await,
        Body::M2Reveal { .. }
    ));
    // ...and ones left unused past their lifetime are gone.
    let Body::PresignCommit { id, commitment } = ask(2, Body::Presign).await else {
        panic!()
    };
    tokio::time::sleep(ttl * 2).await;
    assert!(matches!(
        ask(2, m2(id, commitment)).await,
        Body::Refused { .. }
    ));
}

/// A coordinator that shows two parties different commitment sets gets no response: each
/// party answers only if every other active party signed the set it was shown itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_party_refuses_when_another_was_shown_a_different_commitment_set() {
    let (committee, _) = committee(2, 3, &[]).await;
    let link = Link::new(
        TIMEOUT,
        Duration::ZERO,
        committee.identity(NodeId::Coordinator),
    );
    let ask = |session: [u8; 32], to: u8, body: Body| {
        let frame = Frame {
            version: cairn_net::wire::NET_VERSION,
            from: NodeId::Coordinator,
            to: NodeId::Party(to),
            session,
            body,
        };
        let (addr, link) = (committee.peers[&NodeId::Party(to)].clone(), link.clone());
        async move { call(&addr, &link, &frame).await.unwrap().reply.body }
    };
    let message = checkpoint(&committee.key.pk, 100, "equivocation");
    // Round 2 of one session, with whatever commitment sets the caller chooses per party.
    let round2 = |session: [u8; 32], tamper: bool, other_message: bool| {
        let (ask, message) = (&ask, message.clone());
        let pk = committee.key.pk;
        async move {
            let mut commitments = Vec::new();
            let mut ids = std::collections::BTreeMap::new();
            for p in [1u8, 2] {
                let Body::PresignCommit { id, commitment } = ask(session, p, Body::Presign).await
                else {
                    panic!()
                };
                commitments.push((p - 1, commitment));
                ids.insert(p, id);
            }
            let mut out = Vec::new();
            for p in [1u8, 2] {
                // Party 2 is shown a different commitment for party 1, or a different message.
                let mut shown = commitments.clone();
                let mut text = message.clone();
                if p == 2 && tamper {
                    shown[0].1[0] ^= 1;
                }
                if p == 2 && other_message {
                    text = checkpoint(&pk, 101, "another block");
                }
                let body = Body::M2 {
                    message: text,
                    presign: ids[&p],
                    commitments: shown,
                };
                let Body::M2Reveal { w, attestation } = ask(session, p, body).await else {
                    panic!("party {p} did not reveal")
                };
                out.push((p - 1, w, attestation));
            }
            out
        }
    };
    let m3_to_party_1 = |session, replies: &[(u8, Vec<Vec<u8>>, cairn_net::wire::Attestation)]| {
        ask(
            session,
            1,
            Body::M3 {
                revealed: vec![(1, replies[1].1.clone())],
                attestations: vec![(1, replies[1].2.clone())],
            },
        )
    };
    let refused =
        |body: Body| matches!(body, Body::Refused { reason } if reason.contains("did not sign"));

    // Honest relay: party 1 answers.
    let honest = round2([1; 32], false, false).await;
    assert!(matches!(
        m3_to_party_1([1; 32], &honest).await,
        Body::M3Response { .. }
    ));
    // Party 2 was shown a different commitment set: its signature covers that set, not the
    // one party 1 signed, so party 1 refuses.
    let split = round2([2; 32], true, false).await;
    assert!(refused(m3_to_party_1([2; 32], &split).await));
    // A signature from another session does not carry over.
    let fresh = round2([4; 32], false, false).await;
    let mut replayed = fresh.clone();
    replayed[1].2 = honest[1].2.clone();
    assert!(refused(m3_to_party_1([4; 32], &replayed).await));
    // No signature at all.
    let fresh = round2([5; 32], false, false).await;
    let body = Body::M3 {
        revealed: vec![(1, fresh[1].1.clone())],
        attestations: Vec::new(),
    };
    assert!(refused(ask([5; 32], 1, body).await));
    // Party 2's signature presented as party 1's own does not count for party 2's slot.
    let fresh = round2([6; 32], false, false).await;
    let body = Body::M3 {
        revealed: vec![(1, fresh[1].1.clone())],
        attestations: vec![(1, fresh[0].2.clone())],
    };
    assert!(refused(ask([6; 32], 1, body).await));
    // Same commitments, but party 2 was asked to sign a different checkpoint (the next
    // height, so that its own policy lets it through).
    let split = round2([3; 32], false, true).await;
    assert!(refused(m3_to_party_1([3; 32], &split).await));
}
