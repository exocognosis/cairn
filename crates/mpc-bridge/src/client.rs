//! Client side of the IPC protocol, and the adapter behind `AttemptEngine`.

use crate::ipc::{read_frame, write_frame, MaskRequest, Reply, Request, ResponseRequest, PARTIES};
use crate::worker::socket_path;
use rand::{rngs::OsRng, Rng};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use threshold_mldsa::engine::{
    check_and_sum, combine_seed, CheckedResponse, MaskOpening, MaskShare, ResponsePart, Sealed,
    SeedPart, Verdict,
};
use threshold_mldsa::fips204::{
    challenge_mul, mat_vec_coeff, red, sample_in_ball, vec_add, vec_sub, vec_zero, Hint, PolyVec,
    C_TILDE_BYTES, K, L, N, Q,
};
use threshold_mldsa::flatten::{to_flat, to_polys};
use threshold_mldsa::protocol::AttemptCtx;
use threshold_mldsa::{Active, AttemptEngine, Fault, FaultKind, GroupPublic};
use zeroize::Zeroize;

/// One party's connection point to the MPC backend.
#[derive(Clone)]
pub struct PartyClient {
    path: PathBuf,
    timeout: Duration,
}

impl PartyClient {
    pub fn new(socket_dir: &Path, party: usize, timeout: Duration) -> Self {
        Self {
            path: socket_path(socket_dir, party),
            timeout,
        }
    }

    /// One request, one reply, over a fresh connection.
    pub fn call(&self, request: &Request) -> io::Result<Reply> {
        let mut stream = UnixStream::connect(&self.path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        write_frame(&mut stream, &request.encode())?;
        Reply::decode(&read_frame(&mut stream)?)
    }
}

/// Hint positions (`i * 256 + j`) to the bit-vector form.
pub fn hint_from_positions(positions: &[u16]) -> Option<Hint> {
    let mut hint: Hint = vec![[false; N]; K];
    for p in positions {
        *hint.get_mut(*p as usize / N)?.get_mut(*p as usize % N)? = true;
    }
    Some(hint)
}

fn random_vec(len: usize) -> PolyVec {
    (0..len)
        .map(|_| std::array::from_fn(|_| OsRng.gen_range(0..Q)))
        .collect()
}

/// Split `v` into three uniform additive shares.
fn split3(v: &PolyVec) -> [PolyVec; PARTIES] {
    let (a, b) = (random_vec(v.len()), random_vec(v.len()));
    let c = vec_sub(&vec_sub(v, &a), &b);
    [a, b, c]
}

/// `AttemptEngine` over the IPC bridge: the non-linear phases run in the three-party backend.
///
/// The in-process tower hands this engine sealed per-signer inputs; the adapter does the public
/// linear checks, re-shares the sums three ways and plays all three party ports. (In the
/// networked deployment each root engine process holds one port and one share instead.)
pub struct IpcEngine {
    clients: [PartyClient; PARTIES],
    pending: Option<([u8; 32], [u8; C_TILDE_BYTES])>,
}

fn unattributed() -> Fault {
    Fault {
        culprit: None,
        kind: FaultKind::Unattributed,
    }
}

impl IpcEngine {
    pub fn connect(socket_dir: &Path, timeout: Duration) -> Self {
        Self {
            clients: std::array::from_fn(|k| PartyClient::new(socket_dir, k + 1, timeout)),
            pending: None,
        }
    }

    fn call_all(&self, requests: [Request; PARTIES]) -> Result<Vec<Reply>, Fault> {
        std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .clients
                .iter()
                .zip(&requests)
                .map(|(c, r)| scope.spawn(move || c.call(r)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().ok().and_then(Result::ok).ok_or_else(unattributed))
                .collect()
        })
    }
}

impl AttemptEngine for IpcEngine {
    fn mask_phase(
        &mut self,
        ctx: &AttemptCtx,
        group: &GroupPublic,
        active: &Active,
        seeds: Sealed<Vec<SeedPart>>,
    ) -> Result<MaskOpening, Fault> {
        self.pending = None;
        let mut k = combine_seed(group, active, seeds)?;
        let (a, b): ([i32; 32], [i32; 32]) = (
            std::array::from_fn(|_| OsRng.gen_range(0..Q)),
            std::array::from_fn(|_| OsRng.gen_range(0..Q)),
        );
        let c: [i32; 32] = std::array::from_fn(|i| red(k[i] as i64 - a[i] as i64 - b[i] as i64));
        k.zeroize();
        let requests = [a, b, c].map(|share| share.to_vec());
        let mut party = 0u8;
        let requests = requests.map(|k_share| {
            party += 1;
            Request::Mask(MaskRequest {
                session: ctx.session,
                party,
                attempt: ctx.attempt,
                mu: ctx.mu,
                rho: group.rho,
                k_share,
            })
        });
        let mut y = vec_zero(L);
        let mut opened = None;
        for reply in self.call_all(requests)? {
            let Reply::MaskOk { c_tilde, y_share } = reply else {
                return Err(unattributed());
            };
            if *opened.get_or_insert(c_tilde) != c_tilde {
                return Err(unattributed());
            }
            y = vec_add(&y, &to_polys(&y_share));
        }
        let c_tilde = opened.ok_or_else(unattributed)?;
        self.pending = Some((ctx.session, c_tilde));
        Ok(MaskOpening {
            c_tilde,
            mask: Sealed::seal(MaskShare::engine_new(y)),
        })
    }

    fn response_phase(
        &mut self,
        ctx: &AttemptCtx,
        group: &GroupPublic,
        active: &Active,
        parts: Sealed<Vec<ResponsePart>>,
    ) -> Result<Verdict, Fault> {
        let (_, c_tilde) = self
            .pending
            .take()
            .filter(|(s, _)| *s == ctx.session)
            .ok_or_else(unattributed)?;
        let CheckedResponse {
            mut z,
            t,
            z_digests,
            ..
        } = check_and_sum(group, active, &c_tilde, parts)?;
        // Re-share three ways. With T_k summing to t and r_k = A z_k - c T_k, the r_k sum to r.
        let c = sample_in_ball(&c_tilde);
        let (z_k, t_k) = (split3(&z), split3(&t));
        let t_flat = [to_flat(&t_k[0]), to_flat(&t_k[1]), to_flat(&t_k[2])];
        let t0 = to_flat(&group.t0);
        let mut party = 0u8;
        let requests = [0, 1, 2].map(|k| {
            party += 1;
            let r_k = vec_sub(
                &mat_vec_coeff(group.a_hat(), &z_k[k]),
                &challenge_mul(&c, &t_k[k]),
            );
            Request::Response(Box::new(ResponseRequest {
                session: ctx.session,
                party,
                z_share: to_flat(&z_k[k]),
                r_share: to_flat(&r_k),
                t0: t0.clone(),
                t: t_flat.clone(),
            }))
        });
        let replies = self.call_all(requests)?;
        if replies.iter().any(|r| r != &replies[0]) {
            return Err(unattributed());
        }
        let verdict = match &replies[0] {
            Reply::Reject => Verdict::Reject,
            Reply::Accept { hint, z: opened } => {
                let sum = opened
                    .iter()
                    .fold(vec_zero(L), |acc, v| vec_add(&acc, &to_polys(v)));
                if sum != z {
                    return Err(unattributed());
                }
                Verdict::Accept {
                    hint: hint_from_positions(hint).ok_or_else(unattributed)?,
                    z_digests,
                }
            }
            _ => return Err(unattributed()),
        };
        z.zeroize();
        Ok(verdict)
    }
}
