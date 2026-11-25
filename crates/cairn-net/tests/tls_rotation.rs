//! Certificate rotation and revocation on a live link, driven through the files on disk.

use cairn_net::tls::{pin, rotate, unpin};
use cairn_net::transport::{call, serve, Handler, Reply};
use cairn_net::{Body, ClusterTls, Frame, Link, NodeId, TlsIdentity};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

struct Echo;

impl Handler for Echo {
    fn handle(&self, request: Frame) -> Reply<'_> {
        Box::pin(async move {
            Some(Frame {
                from: request.to,
                to: request.from,
                ..request
            })
        })
    }
}

const PARTY: NodeId = NodeId::Party(1);
const COORD: NodeId = NodeId::Coordinator;

fn link(dir: &Path) -> Link {
    let tls = Arc::new(TlsIdentity::load(dir, COORD).unwrap());
    Link::new(Duration::from_secs(2), Duration::ZERO, tls)
}

async fn start(dir: &Path) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let tls = Arc::new(TlsIdentity::load(dir, PARTY).unwrap());
    tokio::spawn(serve(listener, Arc::new(Echo), Duration::ZERO, tls));
    addr
}

async fn reaches(addr: &str, link: &Link) -> bool {
    let frame = Frame {
        version: cairn_net::wire::NET_VERSION,
        from: COORD,
        to: PARTY,
        session: [3; 32],
        body: Body::Prepare {
            message: b"ping".to_vec(),
        },
    };
    call(addr, link, &frame).await.is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn certificates_rotate_and_revoke_without_an_authority() {
    let root = std::env::temp_dir().join(format!("cairn-tls-rotation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    // Two machines: each has the table and, after this, only needs its own key.
    let (coord, party) = (root.join("coordinator"), root.join("party"));
    let cluster = ClusterTls::generate(&[COORD, PARTY]).unwrap();
    cluster.write(&coord).unwrap();
    cluster.write(&party).unwrap();

    let addr = start(&party).await;
    let first = link(&coord);
    assert!(reaches(&addr, &first).await);

    // Revocation: the party drops the coordinator's certificate. The pooled connection made
    // above stops being served, and so does a fresh one, with nothing restarted.
    assert_eq!(unpin(&party, COORD, None).unwrap(), 1);
    assert!(
        !reaches(&addr, &first).await,
        "revoked certificate still served"
    );
    assert!(!reaches(&addr, &link(&coord)).await);

    // The coordinator makes itself a new certificate; the party pins it and serves it.
    let (old, new) = rotate(&coord, COORD).unwrap();
    assert!(old.is_some() && old.as_deref() != Some(new.as_str()));
    pin(&party, COORD, &new).unwrap();
    let second = link(&coord);
    assert!(reaches(&addr, &second).await);
    assert!(
        !reaches(&addr, &first).await,
        "the replaced certificate must stay out"
    );

    // The party rotates. While both fingerprints are pinned the caller reaches the old
    // process and the restarted one alike.
    let (old, new) = rotate(&party, PARTY).unwrap();
    pin(&coord, PARTY, &new).unwrap();
    assert!(reaches(&addr, &second).await);
    let restarted = start(&party).await;
    assert!(reaches(&restarted, &second).await);

    // Once the old fingerprint is unpinned only the new certificate is reachable.
    assert_eq!(unpin(&coord, PARTY, old.as_deref()).unwrap(), 1);
    assert!(
        !reaches(&addr, &second).await,
        "old server certificate still trusted"
    );
    assert!(reaches(&restarted, &second).await);

    // A certificate nobody pinned, under the right name, gets nowhere.
    let stranger = root.join("stranger");
    rotate(&stranger, COORD).unwrap();
    pin(&stranger, PARTY, &new).unwrap();
    assert!(!reaches(&restarted, &link(&stranger)).await);

    std::fs::remove_dir_all(&root).unwrap();
}
