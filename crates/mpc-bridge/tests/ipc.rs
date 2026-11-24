//! Full IPC round trip against an external worker process.
//!
//! By default each test starts the reference worker (`cairn-mpc-worker`) as a child process.
//! Set `CAIRN_MPC_SOCKET_DIR` to a directory holding `p1.sock`..`p3.sock` to run the same tests
//! against another backend speaking the protocol (the MP-SPDZ bridge).

use cascade_tower::{Tower, TowerParams};
use mpc_bridge::ipc::{FAULT_BLAME, FAULT_UNATTRIBUTED};
use mpc_bridge::{
    hint_from_positions, IpcEngine, MaskRequest, PartyClient, Reply, Request, ResponseRequest,
};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use threshold_mldsa::fips204::{self, vec_add, vec_zero, L, Q};
use threshold_mldsa::flatten::{to_flat, to_polys};
use threshold_mldsa::{deal, AdditiveShare, Gadget, GroupPublic, SignPolicy};

struct Backend {
    dir: PathBuf,
    child: Option<Child>,
}

impl Drop for Backend {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn backend(tag: &str) -> Backend {
    if let Some(dir) = std::env::var_os("CAIRN_MPC_SOCKET_DIR") {
        return Backend {
            dir: dir.into(),
            child: None,
        };
    }
    // Unix socket paths are short (104 bytes on macOS): keep the directory name small.
    let dir = std::env::temp_dir().join(format!("cmw-{}-{tag}", std::process::id()));
    let child = Command::new(env!("CARGO_BIN_EXE_cairn-mpc-worker"))
        .arg("--socket-dir")
        .arg(&dir)
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !(1..=3).all(|p| mpc_bridge::socket_path(&dir, p).exists()) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "worker did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    Backend {
        dir,
        child: Some(child),
    }
}

fn reference(seed: &[u8; 32], msg: &[u8]) -> ([u8; fips204::SIGNATURE_BYTES], u32) {
    fips204::sign_reference(&fips204::keygen_internal(seed), msg)
}

#[test]
fn tower_signs_through_the_external_worker_with_rejections() {
    let backend = backend("tower");
    // A message that needs several attempts, so the rejection-retry loop crosses the IPC boundary.
    let (seed, msg) = (1u8..)
        .map(|s| ([s; 32], vec![s; 12]))
        .find(|(s, m)| reference(s, m).1 >= 3)
        .unwrap();
    let mut tower = Tower::deal(&seed, &TowerParams::default_16(), &mut OsRng).unwrap();
    let mut engine = IpcEngine::connect(&backend.dir, Duration::from_secs(600));
    let out = tower
        .sign(&mut engine, &msg, &SignPolicy::default())
        .unwrap();
    let (expect, rejections) = reference(&seed, &msg);
    assert_eq!(
        out.signature, expect,
        "IPC backend must reproduce the deterministic FIPS 204 signature"
    );
    assert_eq!(out.report.rejections, rejections);
    assert!(fips204::verify_standard(
        tower.public_key(),
        &msg,
        &out.signature
    ));
}

/// Three additive holders, as the root engines are: each owns one party port.
struct Trio {
    group: GroupPublic,
    shares: Vec<AdditiveShare>,
    clients: Vec<PartyClient>,
    mu: [u8; 64],
    session: [u8; 32],
}

fn trio(dir: &Path, seed: &[u8; 32], msg: &[u8], session: u8) -> Trio {
    let (group, key_shares) = deal(seed, &[Gadget::new(3, 3).unwrap()], &mut OsRng).unwrap();
    let set = [1u8, 2, 3];
    let shares = key_shares
        .iter()
        .map(|s| s.flatten(threshold_mldsa::keys::lagrange_at_zero(s.path[0], &set)))
        .collect();
    let clients = (1..=3)
        .map(|p| PartyClient::new(dir, p, Duration::from_secs(600)))
        .collect();
    let mu = fips204::message_representative(&group.tr, &[], msg);
    Trio {
        group,
        shares,
        clients,
        mu,
        session: [session; 32],
    }
}

impl Trio {
    fn all(&self, requests: Vec<Request>) -> Vec<Reply> {
        std::thread::scope(|s| {
            let handles: Vec<_> = self
                .clients
                .iter()
                .zip(&requests)
                .map(|(c, r)| s.spawn(move || c.call(r).unwrap()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    }

    fn mask(&self, attempt: u32) -> ([u8; 48], Vec<Vec<i32>>) {
        let requests = (0..3)
            .map(|k| {
                Request::Mask(MaskRequest {
                    session: self.session,
                    party: k as u8 + 1,
                    attempt,
                    mu: self.mu,
                    rho: self.group.rho,
                    k_share: self.shares[k].k.clone(),
                })
            })
            .collect();
        let mut c_tilde = None;
        let mut ys = Vec::new();
        for reply in self.all(requests) {
            let Reply::MaskOk {
                c_tilde: c,
                y_share,
            } = reply
            else {
                panic!("mask phase failed: {reply:?}")
            };
            assert_eq!(*c_tilde.get_or_insert(c), c);
            ys.push(y_share);
        }
        (c_tilde.unwrap(), ys)
    }

    fn respond(
        &self,
        c_tilde: &[u8; 48],
        ys: &[Vec<i32>],
        tamper: impl Fn(usize, &mut Vec<i32>, &mut Vec<i32>),
    ) -> Vec<Reply> {
        let a_hat = self.group.a_hat();
        let t: Vec<Vec<i32>> = self
            .shares
            .iter()
            .map(|s| to_flat(&s.verification(a_hat)))
            .collect();
        let requests = (0..3)
            .map(|k| {
                let (z, r) = self.shares[k].respond(a_hat, &to_polys(&ys[k]), c_tilde);
                let (mut z, mut r) = (to_flat(&z), to_flat(&r));
                tamper(k, &mut z, &mut r);
                Request::Response(Box::new(ResponseRequest {
                    session: self.session,
                    party: k as u8 + 1,
                    z_share: z,
                    r_share: r,
                    t0: to_flat(&self.group.t0),
                    t: [t[0].clone(), t[1].clone(), t[2].clone()],
                }))
            })
            .collect();
        self.all(requests)
    }
}

#[test]
fn three_additive_holders_reach_the_reference_signature() {
    let backend = backend("trio");
    let (seed, msg) = ([77u8; 32], b"root engines".to_vec());
    let trio = trio(&backend.dir, &seed, &msg, 1);
    let mut attempt = 0;
    let signature = loop {
        let (c_tilde, ys) = trio.mask(attempt);
        let replies = trio.respond(&c_tilde, &ys, |_, _, _| {});
        assert!(
            replies.iter().all(|r| r == &replies[0]),
            "all parties see the same opening"
        );
        match &replies[0] {
            Reply::Reject => attempt += 1,
            Reply::Accept { hint, z } => {
                let sum = z
                    .iter()
                    .fold(vec_zero(L), |acc, v| vec_add(&acc, &to_polys(v)));
                break fips204::pack_signature(&c_tilde, &sum, &hint_from_positions(hint).unwrap());
            }
            other => panic!("unexpected reply {other:?}"),
        }
    };
    let (expect, rejections) = reference(&seed, &msg);
    assert_eq!(signature, expect);
    assert_eq!(attempt, rejections);
    assert_eq!(
        trio.clients[0].call(&Request::Close(trio.session)).unwrap(),
        Reply::Closed
    );
}

#[test]
fn deviating_parties_are_caught_before_any_verdict() {
    let backend = backend("fault");
    let trio = trio(&backend.dir, &[78u8; 32], b"faults", 2);

    // Party 2 sends an r share that does not match its verification share: blamed by number.
    let (c_tilde, ys) = trio.mask(0);
    let replies = trio.respond(&c_tilde, &ys, |k, _, r| {
        if k == 1 {
            r[0] = (r[0] + 1) % Q;
        }
    });
    assert!(
        replies.iter().all(|r| matches!(
            r,
            Reply::Fault {
                code: FAULT_BLAME,
                party: 2,
                ..
            }
        )),
        "{replies:?}"
    );

    // Party 3 uses a different mask share (consistent z and r): detected, not attributable.
    let (c_tilde, mut ys) = trio.mask(1);
    ys[2][0] = (ys[2][0] + 1) % Q;
    let replies = trio.respond(&c_tilde, &ys, |_, _, _| {});
    assert!(
        replies.iter().all(|r| matches!(
            r,
            Reply::Fault {
                code: FAULT_UNATTRIBUTED,
                ..
            }
        )),
        "{replies:?}"
    );
}
