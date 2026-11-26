//! Distributed key generation over real TLS sockets, then signing with the generated key.

use cairn_net::dkg::{self, DkgNode, Identity, Roster};
use cairn_net::flat::{party_share_file, read_committee, read_party_share, run_party};
use cairn_net::policy::{key_id, Checkpoint, Policy};
use cairn_net::transport::serve;
use cairn_net::{
    ClusterTls, FaultMode, FlatCoordinator, Link, NetPolicy, NodeId, PartyNode, Peers,
};
use std::sync::Arc;
use std::time::Duration;
use threshold_mldsa::fips204;
use threshold_mldsa::mithril::all_subsets;
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread")]
async fn a_committee_generates_its_key_without_a_dealer_and_then_signs() {
    let (t, n) = (3u8, 4usize);
    let work = std::env::temp_dir().join(format!("cairn-dkg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    // Each party makes its own identity; only the public halves go into the roster.
    let identities: Vec<Identity> = (0..n).map(|_| Identity::generate().unwrap()).collect();
    let roster = Roster {
        threshold: t,
        identities: identities.iter().map(Identity::public).collect(),
    };
    let ids: Vec<NodeId> = (1..=n as u8).map(NodeId::Party).collect();
    let tls = ClusterTls::generate(&[ids.clone(), vec![NodeId::Coordinator]].concat()).unwrap();

    let mut peers = Peers::new();
    let mut tasks = Vec::new();
    for (id, identity) in ids.iter().zip(&identities) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        peers.insert(*id, listener.local_addr().unwrap().to_string());
        let node = Arc::new(DkgNode::new(
            *id,
            roster.clone(),
            identity,
            work.join(id.to_string()),
        ));
        tasks.push(tokio::spawn(serve(
            listener,
            node,
            Duration::ZERO,
            Arc::new(tls.identity(*id).unwrap()),
        )));
    }
    let coordinator_tls = Arc::new(tls.identity(NodeId::Coordinator).unwrap());
    let link = Link::new(
        Duration::from_secs(10),
        Duration::ZERO,
        coordinator_tls.clone(),
    );
    let pk = dkg::run(&roster, &peers, &link).await.unwrap();
    tasks.iter().for_each(|t| t.abort());

    // Every party wrote the same public key and only its own subsets' secrets.
    let subsets = all_subsets(t as usize, n);
    let mut signing_peers = Peers::new();
    let mut signing_tasks = Vec::new();
    let mut stats = Vec::new();
    let mut key = None;
    for id in &ids {
        let dir = work.join(id.to_string());
        let committee = read_committee(&dir.join("committee.bin")).unwrap();
        assert_eq!(committee.pk, pk);
        let share = read_party_share(&party_share_file(&dir, *id)).unwrap();
        assert!(
            share.subsets().len() < subsets.len(),
            "{id} holds every secret"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        signing_peers.insert(*id, listener.local_addr().unwrap().to_string());
        let committee = Arc::new(committee);
        let node = PartyNode::new(
            *id,
            committee.clone(),
            share,
            FaultMode::None,
            cairn_net::policy::PosCheckpointPolicy::from(Policy::ephemeral(&pk)),
            Arc::new(tls.identity(*id).unwrap()),
        );
        stats.push(node.stats.clone());
        signing_tasks.push(tokio::spawn(run_party(listener, node, Duration::ZERO)));
        key = Some(committee);
    }

    // The generated key signs through the three-round protocol.
    let policy = NetPolicy {
        round_timeout: Duration::from_secs(5),
        ..NetPolicy::default()
    };
    let mut coordinator =
        FlatCoordinator::new(key.unwrap(), signing_peers, policy, coordinator_tls);
    let message = Checkpoint {
        chain: "cosmos:cairn-test-1".into(),
        epoch: 1,
        height: 100,
        block_hash: vec![3; 32],
        finality_commitment: vec![4; 32],
        key_id: key_id(&pk),
    }
    .message();
    let (signature, _) = coordinator.sign(&message).await.unwrap();
    assert!(fips204::verify_standard(&pk, &message, &signature));
    // Each party's own counters saw the signature being made.
    let responded = stats
        .iter()
        .filter(|s| !s.render().contains("cairn_party_responses_total 0\n"))
        .count();
    assert!(responded >= 2, "{responded} parties counted a response");
    signing_tasks.iter().for_each(|t| t.abort());
    let _ = std::fs::remove_dir_all(&work);
}
