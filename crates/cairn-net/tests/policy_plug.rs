//! The party's policy is a plug: the same committee code signs an arbitrary payload under
//! one policy and refuses it under the checkpoint rules.

use cairn_net::flat::{FlatCoordinator, LocalCommittee};
use cairn_net::{NetError, NetPolicy, NodeId};
use cairn_policy::{PolicyEngine, PolicyError, SignContext, Unrestricted};
use std::time::Duration;
use threshold_mldsa::fips204::verify_standard;

/// A stand-in for an organization's rule: only payloads with an agreed prefix.
struct Prefix(&'static [u8]);

impl PolicyEngine for Prefix {
    fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError> {
        assert!(ctx.signers.contains(&ctx.party));
        if payload.starts_with(self.0) {
            Ok(())
        } else {
            Err(PolicyError::Refused(
                "payload lacks the agreed prefix".into(),
            ))
        }
    }
}

async fn committee(
    policy: impl Fn(&[u8]) -> Box<dyn PolicyEngine>,
) -> (LocalCommittee, FlatCoordinator) {
    let committee =
        LocalCommittee::start_policy(2, 3, &[], Duration::ZERO, Duration::from_secs(60), policy)
            .await
            .unwrap();
    let coordinator = FlatCoordinator::new(
        committee.key.clone(),
        committee.peers.clone(),
        NetPolicy {
            round_timeout: Duration::from_secs(20),
            ..NetPolicy::default()
        },
        committee.identity(NodeId::Coordinator),
    );
    (committee, coordinator)
}

#[tokio::test(flavor = "multi_thread")]
async fn parties_sign_what_their_own_policy_allows() {
    let payload = b"wire transfer 42, approved";

    let (c, mut coordinator) = committee(|_| Box::new(Unrestricted)).await;
    let (signature, _) = coordinator.sign(payload).await.unwrap();
    assert!(verify_standard(&c.key.pk, payload, &signature));

    let (c, mut coordinator) = committee(|_| Box::new(Prefix(b"wire transfer"))).await;
    let (signature, _) = coordinator.sign(payload).await.unwrap();
    assert!(verify_standard(&c.key.pk, payload, &signature));
    assert!(matches!(
        coordinator.sign(b"something else").await,
        Err(NetError::Policy(reason)) if reason == "payload lacks the agreed prefix"
    ));

    // The default: the checkpoint rules refuse a payload that is not a checkpoint.
    let (_c, mut coordinator) = committee(|pk| {
        Box::new(cairn_policy::PosCheckpointPolicy::from(
            cairn_policy::pos::Policy::ephemeral(pk),
        ))
    })
    .await;
    assert!(matches!(
        coordinator.sign(payload).await,
        Err(NetError::Policy(_))
    ));
}

/// A policy that takes a while, as one that runs a program or calls a service may.
struct Slow(Duration);

impl PolicyEngine for Slow {
    fn authorize_sign(&self, _: &SignContext, _: &[u8]) -> Result<(), PolicyError> {
        std::thread::sleep(self.0);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_slow_policy_does_not_hold_up_the_party() {
    use cairn_net::transport::call;
    use cairn_net::{Body, Frame, Link};
    let slow = Duration::from_millis(1500);
    let (c, _) = committee(move |_| Box::new(Slow(slow))).await;
    let link = Link::new(
        Duration::from_secs(20),
        Duration::ZERO,
        c.identity(NodeId::Coordinator),
    );
    let ask = |session: [u8; 32], body: Body| {
        let frame = Frame {
            version: cairn_net::wire::NET_VERSION,
            from: NodeId::Coordinator,
            to: NodeId::Party(1),
            session,
            body,
        };
        let (addr, link) = (c.peers[&NodeId::Party(1)].clone(), link.clone());
        async move { call(&addr, &link, &frame).await.unwrap().reply.body }
    };
    // A signing request whose policy check is still running...
    let waiting = tokio::spawn(ask(
        [1; 32],
        Body::M2 {
            message: b"anything".to_vec(),
            presign: [0; 32],
            commitments: Vec::new(),
        },
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    // ...does not stop the same party, on its one network thread, answering another.
    let started = std::time::Instant::now();
    let reply = ask([2; 32], Body::Presign).await;
    assert!(matches!(reply, Body::PresignCommit { .. }));
    assert!(
        started.elapsed() < Duration::from_millis(800),
        "{:?}",
        started.elapsed()
    );
    assert!(!waiting.is_finished());
    assert!(matches!(waiting.await.unwrap(), Body::Refused { .. }));
}
