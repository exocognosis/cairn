//! Reference worker: the 3-party MPC backend as a clear-text ideal functionality.
//!
//! It listens on `p1.sock`, `p2.sock` and `p3.sock`, waits until all three parties have sent the
//! request for a phase, computes the phase on the reconstructed values and answers each party.
//! It is deterministic: equal inputs give equal outputs, including the split of the mask.
//!
//! This process sees the signing seed, the mask and every rejected candidate. It exists so the
//! IPC path, the rejection-retry loop and the root engines can be exercised on any machine. The
//! MP-SPDZ program under `mpc/mp-spdz/` is the backend meant to replace it.

use crate::ipc::{
    read_frame, write_frame, MaskRequest, Reply, Request, ResponseRequest, FAULT_BLAME,
    FAULT_PROTOCOL, FAULT_UNATTRIBUTED, PARTIES,
};
use std::collections::HashMap;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use threshold_mldsa::fips204::{
    self, challenge_mul, commit_mask, expand_a, expand_mask, finish_attempt, inf_norm,
    mat_vec_coeff, red, sample_in_ball, vec_add, vec_sub, PolyVec, BETA, C_TILDE_BYTES, K, L, N, Q,
};
use threshold_mldsa::flatten::{to_flat, to_polys};
use zeroize::Zeroize;

pub fn socket_path(dir: &Path, party: usize) -> PathBuf {
    dir.join(format!("p{party}.sock"))
}

struct MaskOut {
    c_tilde: [u8; C_TILDE_BYTES],
    y: [Vec<i32>; PARTIES],
    w: PolyVec,
}

#[derive(Default)]
struct Round {
    attempt: u32,
    masks: [Option<MaskRequest>; PARTIES],
    mask_out: Option<Result<MaskOut, Reply>>,
    responses: [Option<Box<ResponseRequest>>; PARTIES],
    response_out: Option<Reply>,
}

struct Shared {
    rounds: Mutex<HashMap<[u8; 32], Round>>,
    ready: Condvar,
    /// How long one party waits for the other two to join a phase.
    rendezvous: Duration,
}

fn fault(code: u8, party: u8, message: &str) -> Reply {
    Reply::Fault {
        code,
        party,
        message: message.into(),
    }
}

fn compute_mask(
    session: &[u8; 32],
    masks: &[Option<MaskRequest>; PARTIES],
) -> Result<MaskOut, Reply> {
    let m: Vec<&MaskRequest> = masks.iter().flatten().collect();
    if m.iter().any(|x| x.mu != m[0].mu || x.rho != m[0].rho) {
        return Err(fault(FAULT_PROTOCOL, 0, "parties disagree on mu or rho"));
    }
    let mut k_elems: Vec<i32> = (0..32)
        .map(|i| red(m.iter().map(|x| x.k_share[i] as i64).sum::<i64>()))
        .collect();
    if k_elems.iter().any(|v| *v > 255) {
        k_elems.zeroize();
        return Err(fault(
            FAULT_UNATTRIBUTED,
            0,
            "seed shares do not sum to bytes",
        ));
    }
    let mut k: [u8; 32] = std::array::from_fn(|i| k_elems[i] as u8);
    k_elems.zeroize();
    // Deterministic FIPS 204 variant (rnd = 0^32); kappa = 5 * attempt.
    let mut rho_pp = fips204::mask_seed(&k, &[0u8; 32], &m[0].mu);
    let y = expand_mask(&rho_pp, (m[0].attempt as usize * L) as u16);
    rho_pp.zeroize();
    let (w, c_tilde) = commit_mask(&expand_a(&m[0].rho), &y, &m[0].mu);

    // Deterministic additive split of y, keyed by the secret seed so it is not predictable.
    let mut stream = vec![0u8; 2 * L * N * 4 * 2];
    fips204::shake256(
        &[
            b"cairn/ref-worker/y-split/v1",
            &k,
            session,
            &m[0].attempt.to_le_bytes(),
        ],
        &mut stream,
    );
    k.zeroize();
    let mut words = stream
        .chunks(4)
        .map(|c| (u32::from_le_bytes(c.try_into().unwrap()) & 0x7f_ffff) as i32);
    let mut draw = || -> Vec<i32> {
        let mut out = Vec::with_capacity(L * N);
        while out.len() < L * N {
            // The stream is twice the expected need; fall back to a fixed value if it runs dry.
            match words.next() {
                Some(v) if v < Q => out.push(v),
                Some(_) => {}
                None => out.push(0),
            }
        }
        out
    };
    let (y1, y2) = (draw(), draw());
    let y3 = to_flat(&vec_sub(&vec_sub(&y, &to_polys(&y1)), &to_polys(&y2)));
    Ok(MaskOut {
        c_tilde,
        y: [y1, y2, y3],
        w,
    })
}

fn compute_response(
    mask: &MaskOut,
    rho: &[u8; 32],
    responses: &[Option<Box<ResponseRequest>>; PARTIES],
) -> Reply {
    let r: Vec<&ResponseRequest> = responses.iter().flatten().map(|b| b.as_ref()).collect();
    if r.iter().any(|x| x.t0 != r[0].t0 || x.t != r[0].t) {
        return fault(
            FAULT_PROTOCOL,
            0,
            "parties disagree on t0 or the verification shares",
        );
    }
    let a_hat = expand_a(rho);
    let c = sample_in_ball(&mask.c_tilde);
    let (mut z, mut rr) = (fips204::vec_zero(L), fips204::vec_zero(K));
    for (k, part) in r.iter().enumerate() {
        let (z_k, r_k) = (to_polys(&part.z_share), to_polys(&part.r_share));
        // Per-party linear check against its public verification share: A z_k - r_k = c T_k.
        if vec_sub(&mat_vec_coeff(&a_hat, &z_k), &r_k) != challenge_mul(&c, &to_polys(&r[0].t[k])) {
            return fault(
                FAULT_BLAME,
                k as u8 + 1,
                "response share fails its verification share",
            );
        }
        z = vec_add(&z, &z_k);
        rr = vec_add(&rr, &r_k);
    }
    // r must be w - c s2: the parties used the mask shares they were given.
    if inf_norm(&vec_sub(&rr, &mask.w)) > BETA {
        return fault(
            FAULT_UNATTRIBUTED,
            0,
            "response does not match the committed mask",
        );
    }
    let ct0 = challenge_mul(&c, &to_polys(&r[0].t0));
    let reply = match finish_attempt(&z, &rr, &ct0) {
        Ok(hint) => Reply::Accept {
            hint: hint
                .iter()
                .enumerate()
                .flat_map(|(i, p)| {
                    p.iter()
                        .enumerate()
                        .filter(|(_, b)| **b)
                        .map(move |(j, _)| (i * N + j) as u16)
                })
                .collect(),
            z: [
                r[0].z_share.clone(),
                r[1].z_share.clone(),
                r[2].z_share.clone(),
            ],
        },
        // One answer for all four abort conditions.
        Err(_) => Reply::Reject,
    };
    z.zeroize();
    rr.zeroize();
    reply
}

fn handle(shared: &Shared, party: usize, request: Request) -> Reply {
    let deadline = Instant::now() + shared.rendezvous;
    let mut rounds = shared.rounds.lock().expect("worker state");
    match request {
        Request::Close(session) => {
            rounds.remove(&session);
            Reply::Closed
        }
        Request::Mask(m) => {
            if m.party as usize != party {
                return fault(
                    FAULT_PROTOCOL,
                    party as u8,
                    "party number does not match the socket",
                );
            }
            let (session, attempt) = (m.session, m.attempt);
            let round = rounds.entry(session).or_default();
            if round.attempt != attempt || round.response_out.is_some() {
                *round = Round {
                    attempt,
                    ..Round::default()
                };
            }
            if round.mask_out.is_none() {
                round.masks[party - 1] = Some(m);
                if round.masks.iter().all(Option::is_some) {
                    round.mask_out = Some(compute_mask(&session, &round.masks));
                    shared.ready.notify_all();
                }
            }
            loop {
                match rounds
                    .get(&session)
                    .filter(|r| r.attempt == attempt)
                    .map(|r| &r.mask_out)
                {
                    None => return fault(FAULT_PROTOCOL, 0, "attempt superseded"),
                    Some(Some(Ok(out))) => {
                        return Reply::MaskOk {
                            c_tilde: out.c_tilde,
                            y_share: out.y[party - 1].clone(),
                        }
                    }
                    Some(Some(Err(reply))) => return reply.clone(),
                    Some(None) => {}
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return fault(
                        FAULT_PROTOCOL,
                        0,
                        "the other parties did not join the mask phase",
                    );
                }
                rounds = shared
                    .ready
                    .wait_timeout(rounds, left)
                    .expect("worker state")
                    .0;
            }
        }
        Request::Response(r) => {
            if r.party as usize != party {
                return fault(
                    FAULT_PROTOCOL,
                    party as u8,
                    "party number does not match the socket",
                );
            }
            let session = r.session;
            let Some(round) = rounds
                .get_mut(&session)
                .filter(|x| matches!(x.mask_out, Some(Ok(_))))
            else {
                return fault(FAULT_PROTOCOL, 0, "no mask phase for this session");
            };
            let attempt = round.attempt;
            if round.response_out.is_none() {
                round.responses[party - 1] = Some(r);
                if round.responses.iter().all(Option::is_some) {
                    let Some(Ok(mask)) = &round.mask_out else {
                        unreachable!("filtered above")
                    };
                    let rho = round.masks[0].as_ref().expect("mask phase ran").rho;
                    round.response_out = Some(compute_response(mask, &rho, &round.responses));
                    round.responses = Default::default();
                    shared.ready.notify_all();
                }
            }
            loop {
                match rounds
                    .get(&session)
                    .filter(|x| x.attempt == attempt)
                    .map(|x| &x.response_out)
                {
                    None => return fault(FAULT_PROTOCOL, 0, "attempt superseded"),
                    Some(Some(reply)) => return reply.clone(),
                    Some(None) => {}
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return fault(
                        FAULT_PROTOCOL,
                        0,
                        "the other parties did not join the response phase",
                    );
                }
                rounds = shared
                    .ready
                    .wait_timeout(rounds, left)
                    .expect("worker state")
                    .0;
            }
        }
    }
}

fn connection(shared: Arc<Shared>, party: usize, mut stream: UnixStream) {
    while let Ok(payload) = read_frame(&mut stream) {
        let reply = match Request::decode(&payload) {
            Ok(request) => handle(&shared, party, request),
            Err(e) => fault(FAULT_PROTOCOL, 0, &e.to_string()),
        };
        if write_frame(&mut stream, &reply.encode()).is_err() {
            break;
        }
    }
}

/// A running reference worker. Dropping it stops the listeners and removes the sockets.
pub struct Worker {
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    listeners: Vec<JoinHandle<()>>,
}

impl Worker {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Block forever (for the standalone process).
    pub fn join(mut self) {
        for l in self.listeners.drain(..) {
            let _ = l.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for l in self.listeners.drain(..) {
            let _ = l.join();
        }
        for party in 1..=PARTIES {
            let _ = std::fs::remove_file(socket_path(&self.dir, party));
        }
    }
}

/// Listen on the three party sockets in `dir`. `rendezvous` bounds how long a party waits for
/// the other two in each phase.
pub fn serve(dir: &Path, rendezvous: Duration) -> io::Result<Worker> {
    std::fs::create_dir_all(dir)?;
    let shared = Arc::new(Shared {
        rounds: Mutex::new(HashMap::new()),
        ready: Condvar::new(),
        rendezvous,
    });
    let stop = Arc::new(AtomicBool::new(false));
    let mut listeners = Vec::new();
    for party in 1..=PARTIES {
        let path = socket_path(dir, party);
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let (shared, stop) = (shared.clone(), stop.clone());
        listeners.push(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let shared = shared.clone();
                        if stream.set_nonblocking(false).is_ok() {
                            std::thread::spawn(move || connection(shared, party, stream));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        }));
    }
    Ok(Worker {
        dir: dir.to_path_buf(),
        stop,
        listeners,
    })
}
