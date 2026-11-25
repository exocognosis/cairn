//! Prototype of the three-round threshold ML-DSA protocol of "Efficient Threshold ML-DSA"
//! (Celi, del Pino, Delerue, Espitau, Niot, Prest; USENIX Security 2026), known as Mithril,
//! for ML-DSA-65.
//!
//! No generic MPC and no `ExpandMask`: every signer samples its own mask in a hyperball,
//! rejection-samples its own response, and the sum is a signature that any FIPS 204 verifier
//! accepts. The signature is *not* the one a deterministic FIPS 204 signer would produce.
//!
//! What is here follows the paper's Figures 4 to 7 and the ML-DSA-65 parameter table (its
//! Figure 10): replicated short secret sharing with a trusted dealer, `K` parallel repetitions,
//! imbalanced hyperball rejection, public combine.
//!
//! **Prototype status.** Written from the paper, not checked against the authors' code. The
//! hyperball sampler uses `f64` and Box-Muller and nothing is constant time. The share partition
//! uses the paper's tables, and distributed key generation (its Appendix D) lives in
//! `cairn-net::dkg`. It shows that the approach produces
//! standard signatures at the published parameters and what it costs; it is not a secure
//! implementation.

use crate::fips204::{
    self, centered, challenge_mul, decompose, expand_a, high_bits, hint_weight, inf_norm,
    mat_vec_coeff, message_representative, red, sample_in_ball, shake256, vec_add, vec_sub,
    vec_zero, w1_encode, Hint, MatrixHat, Poly, PolyVec, BETA, C_TILDE_BYTES, D, GAMMA1, GAMMA2, K,
    L, N, OMEGA, PUBLIC_KEY_BYTES, SIGNATURE_BYTES,
};
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;

/// Expansion factor for the first `L` coordinates of the randomness (all ML-DSA-65 sets).
pub const NU: f64 = 6.0;
const DIM: usize = N * (L + K);

/// Parameters for one `(T, N)`: target radius `r`, randomness radius `r'`, repetitions `K`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    pub t: usize,
    pub n: usize,
    pub r: f64,
    pub r_prime: f64,
    pub reps: usize,
}

/// The paper's ML-DSA-65 parameter sets (success probability about 1/2 per execution).
pub fn params_65(t: usize, n: usize) -> Option<Params> {
    let (r, r_prime, reps) = match (t, n) {
        (2, 2) => (501_495.0, 501_613.0, 3),
        (2, 3) => (540_212.0, 540_378.0, 5),
        (3, 3) => (510_387.0, 510_504.0, 9),
        (2, 4) => (540_212.0, 540_378.0, 6),
        (3, 4) => (506_761.0, 506_928.0, 20),
        (4, 4) => (433_594.0, 433_711.0, 26),
        (2, 5) => (552_371.0, 552_575.0, 8),
        (3, 5) => (552_909.0, 553_145.0, 62),
        (4, 5) => (474_331.0, 474_535.0, 205),
        (5, 5) => (425_914.0, 426_032.0, 78),
        (2, 6) => (571_208.0, 571_412.0, 8),
        (3, 6) => (536_793.0, 537_058.0, 95),
        (4, 6) => (488_704.0, 488_969.0, 804),
        (5, 6) => (461_324.0, 461_529.0, 1200),
        (6, 6) => (414_896.0, 415_013.0, 250),
        _ => return None,
    };
    Some(Params {
        t,
        n,
        r,
        r_prime,
        reps,
    })
}

/// A subset of parties, as a sorted list of 0-based indices.
pub type Subset = Vec<u8>;

fn subsets(n: usize, size: usize) -> Vec<Subset> {
    (0u32..1 << n)
        .filter(|m| m.count_ones() as usize == size)
        .map(|m| (0..n as u8).filter(|i| m >> i & 1 == 1).collect())
        .collect()
}

/// Public key material: a standard ML-DSA-65 public key plus what combine needs.
pub struct GroupKey {
    pub pk: [u8; PUBLIC_KEY_BYTES],
    pub rho: [u8; 32],
    pub tr: [u8; 64],
    pub t1: PolyVec,
    pub params: Params,
    /// `t_S = A s1_S + s2_S` for every subset: public, and what lets anyone check a single
    /// party's response. Empty for keys made before these were kept.
    pub subset_keys: BTreeMap<Subset, PolyVec>,
    a_hat: MatrixHat,
}

/// One party's replicated shares: the short secret `(s1_I, s2_I)` of every subset it is in.
pub struct PartyKey {
    pub index: u8,
    shares: BTreeMap<Subset, (PolyVec, PolyVec)>,
}

fn flat(v: &PolyVec) -> Vec<i32> {
    v.iter().flatten().copied().collect()
}

fn polys(flat: &[i32], count: usize) -> Option<PolyVec> {
    (flat.len() == count * N && flat.iter().all(|c| (0..fips204::Q).contains(c))).then(|| {
        flat.chunks(N)
            .map(|c| c.try_into().expect("whole polynomial"))
            .collect()
    })
}

/// Pack field elements at 23 bits each (they are below 2^23).
fn pack23(v: &PolyVec) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * N * 23 / 8 + 1);
    let (mut acc, mut bits) = (0u64, 0u32);
    for c in v.iter().flatten() {
        acc |= (*c as u64) << bits;
        bits += 23;
        while bits >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 {
        out.push(acc as u8);
    }
    out
}

fn unpack23(bytes: &[u8], count: usize) -> Option<PolyVec> {
    if bytes.len() != (count * N * 23).div_ceil(8) {
        return None;
    }
    let (mut acc, mut bits, mut pos) = (0u64, 0u32, 0usize);
    let mut flat = Vec::with_capacity(count * N);
    for _ in 0..count * N {
        while bits < 23 {
            acc |= (bytes[pos] as u64) << bits;
            pos += 1;
            bits += 8;
        }
        flat.push((acc & 0x7f_ffff) as i32);
        acc >>= 23;
        bits -= 23;
    }
    polys(&flat, count)
}

/// `w` of one repetition (`K` polynomials) to and from its packed wire form.
pub fn w_to_wire(w: &PolyVec) -> Vec<u8> {
    pack23(w)
}

pub fn w_from_wire(v: &[u8]) -> Option<PolyVec> {
    unpack23(v, K)
}

/// `z1` of one repetition (`L` polynomials) to and from its packed wire form.
pub fn z_to_wire(z: &PolyVec) -> Vec<u8> {
    pack23(z)
}

pub fn z_from_wire(v: &[u8]) -> Option<PolyVec> {
    unpack23(v, L)
}

impl GroupKey {
    /// Public group description for distribution to every node (no secrets).
    pub fn to_bytes(&self) -> Vec<u8> {
        let subset_keys: Vec<(Subset, Vec<u8>)> = self
            .subset_keys
            .iter()
            .map(|(s, t)| (s.clone(), pack23(t)))
            .collect();
        bincode::serialize(&(
            self.params.t as u8,
            self.params.n as u8,
            self.pk.to_vec(),
            flat(&self.t1),
            subset_keys,
        ))
        .expect("group key encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        type Wire = (u8, u8, Vec<u8>, Vec<i32>, Vec<(Subset, Vec<u8>)>);
        let (t, n, pk, t1, wire_keys): Wire = bincode::deserialize(bytes).ok()?;
        let mut subset_keys = BTreeMap::new();
        for (subset, packed) in wire_keys {
            subset_keys.insert(subset, unpack23(&packed, K)?);
        }
        let pk: [u8; PUBLIC_KEY_BYTES] = pk.try_into().ok()?;
        let rho: [u8; 32] = pk[..32].try_into().ok()?;
        let mut tr = [0u8; 64];
        shake256(&[&pk], &mut tr);
        Some(Self {
            pk,
            rho,
            tr,
            t1: polys(&t1, K)?,
            params: params_65(t as usize, n as usize)?,
            subset_keys,
            a_hat: expand_a(&rho),
        })
    }
}

type ShareWire = Vec<(Subset, Vec<i32>, Vec<i32>)>;

impl PartyKey {
    /// Serialize for a share file. The bytes are this party's long-term secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        let shares: ShareWire = self
            .shares
            .iter()
            .map(|(s, (a, b))| (s.clone(), flat(a), flat(b)))
            .collect();
        bincode::serialize(&(self.index, shares)).expect("share encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (index, wire): (u8, ShareWire) = bincode::deserialize(bytes).ok()?;
        let mut shares = BTreeMap::new();
        for (subset, a, b) in wire {
            shares.insert(subset, (polys(&a, L)?, polys(&b, K)?));
        }
        Some(Self { index, shares })
    }
}

impl GroupKey {
    /// Build the public key material from a seed `rho` and the full `t = A s1 + s2`.
    pub fn from_parts(
        t: usize,
        n: usize,
        rho: [u8; 32],
        t_full: &PolyVec,
        subset_keys: BTreeMap<Subset, PolyVec>,
    ) -> Option<Self> {
        let (pk, t1, tr) = fips204::public_key_from_t(&rho, t_full);
        Some(Self {
            pk,
            rho,
            tr,
            t1,
            params: params_65(t, n)?,
            subset_keys,
            a_hat: expand_a(&rho),
        })
    }
}

impl PartyKey {
    /// A party's key from the subset secrets it holds (distributed key generation).
    pub fn from_shares(index: u8, shares: BTreeMap<Subset, (PolyVec, PolyVec)>) -> Self {
        Self { index, shares }
    }

    /// The subsets whose secrets this party holds.
    pub fn subsets(&self) -> Vec<Subset> {
        self.shares.keys().cloned().collect()
    }
}

/// Every subset of `N - T + 1` parties, in a fixed order.
pub fn all_subsets(t: usize, n: usize) -> Vec<Subset> {
    let mut all = subsets(n, n - t + 1);
    all.sort();
    all
}

/// Derive one subset's short secret from its shared seed and the public randomness (the
/// paper's `H_keygen`): the standard ML-DSA secret distribution, expanded from a hash.
pub fn derive_subset_secret(
    subset: &[u8],
    seed: &[u8; 32],
    randomness: &[u8],
) -> (PolyVec, PolyVec) {
    let mut expanded = [0u8; 64];
    shake256(
        &[
            b"cairn/dkg/keygen/v1",
            &[subset.len() as u8],
            subset,
            seed,
            randomness,
        ],
        &mut expanded,
    );
    fips204::expand_s(&expanded)
}

/// `t_S = A s1_S + s2_S` for a subset secret under the matrix seeded by `rho`.
pub fn subset_public(rho: &[u8; 32], secret: &(PolyVec, PolyVec)) -> PolyVec {
    vec_add(&mat_vec_coeff(&expand_a(rho), &secret.0), &secret.1)
}

/// `K` polynomials packed at 23 bits per coefficient, and back.
pub fn pack_k(v: &PolyVec) -> Vec<u8> {
    pack23(v)
}

pub fn unpack_k(bytes: &[u8]) -> Option<PolyVec> {
    unpack23(bytes, K)
}

impl Round1 {
    pub fn index(&self) -> u8 {
        self.index
    }
}

fn short_poly<R: Rng + CryptoRng>(rng: &mut R) -> Poly {
    std::array::from_fn(|_| red(rng.gen_range(-4i64..=4)))
}

/// Trusted-dealer key generation (the paper's Figure 5). One short ML-DSA secret per subset of
/// `N - T + 1` parties; the key is their sum. Any `T` parties hold every secret between them,
/// and any `T - 1` miss at least one.
pub fn keygen<R: Rng + CryptoRng>(
    t: usize,
    n: usize,
    rng: &mut R,
) -> Option<(GroupKey, Vec<PartyKey>)> {
    let params = params_65(t, n)?;
    let rho: [u8; 32] = rng.gen();
    let a_hat = expand_a(&rho);
    let mut parties: Vec<PartyKey> = (0..n as u8)
        .map(|index| PartyKey {
            index,
            shares: BTreeMap::new(),
        })
        .collect();
    let (mut s1, mut s2) = (vec_zero(L), vec_zero(K));
    let mut subset_keys = BTreeMap::new();
    for subset in subsets(n, n - t + 1) {
        let part1: PolyVec = (0..L).map(|_| short_poly(rng)).collect();
        let part2: PolyVec = (0..K).map(|_| short_poly(rng)).collect();
        s1 = vec_add(&s1, &part1);
        s2 = vec_add(&s2, &part2);
        subset_keys.insert(
            subset.clone(),
            vec_add(&mat_vec_coeff(&a_hat, &part1), &part2),
        );
        for i in &subset {
            parties[*i as usize]
                .shares
                .insert(subset.clone(), (part1.clone(), part2.clone()));
        }
    }
    let t_full = vec_add(&mat_vec_coeff(&a_hat, &s1), &s2);
    let (pk, t1, tr) = fips204::public_key_from_t(&rho, &t_full);
    Some((
        GroupKey {
            pk,
            rho,
            tr,
            t1,
            params,
            subset_keys,
            a_hat,
        },
        parties,
    ))
}

/// The paper's optimal assignment (its Algorithm 6) for the canonical active set `{0..T-1}`:
/// for each active party, the subsets (as digit strings) whose secrets it uses.
fn ideal_sharing(t: usize, n: usize) -> Option<&'static [&'static [&'static str]]> {
    Some(match (t, n) {
        (2, 3) => &[&["01", "02"], &["12"]],
        (2, 4) => &[&["013", "023"], &["012", "123"]],
        (3, 4) => &[&["01", "03"], &["12", "13"], &["23", "02"]],
        (2, 5) => &[&["0134", "0234", "0124"], &["1234", "0123"]],
        (3, 5) => &[
            &["034", "013", "014", "023"],
            &["012", "123", "124", "134"],
            &["234", "024"],
        ],
        (4, 5) => &[
            &["01", "03", "04"],
            &["12", "13", "14"],
            &["23", "02", "24"],
            &["34"],
        ],
        (2, 6) => &[&["02345", "01235", "01245"], &["12345", "01234", "01345"]],
        (3, 6) => &[
            &["0134", "0124", "0135", "0345", "0125"],
            &["0145", "1345", "1235", "1234", "1245"],
            &["0235", "0245", "0234", "0123", "2345"],
        ],
        (4, 6) => &[
            &["014", "023", "015", "012", "045"],
            &["135", "134", "125", "145", "124"],
            &["245", "024", "235", "234", "025"],
            &["034", "013", "123", "345", "035"],
        ],
        (5, 6) => &[
            &["01", "02", "05"],
            &["12", "13", "15"],
            &["23", "24", "25"],
            &["03", "34", "35"],
            &["45", "04", "14"],
        ],
        _ => return None,
    })
}

/// Deterministic assignment of every subset's secret to one active party that holds it (the
/// paper's `RSSRecover`). Uses the paper's balanced tables, relabelled for the active set.
pub fn recover_partition(params: &Params, active: &[u8]) -> Option<BTreeMap<u8, Vec<Subset>>> {
    let (t, n) = (params.t, params.n);
    let mut act = active.to_vec();
    act.sort();
    act.dedup();
    if act.len() != t || act.iter().any(|i| *i as usize >= n) {
        return None;
    }
    if t == n {
        return Some(act.iter().map(|i| (*i, vec![vec![*i]])).collect());
    }
    // phi maps canonical indices to real ones: active parties first, the rest after.
    let mut phi: Vec<u8> = act.clone();
    phi.extend((0..n as u8).filter(|i| !act.contains(i)));
    let table = ideal_sharing(t, n)?;
    Some(
        table
            .iter()
            .enumerate()
            .map(|(i, sets)| {
                let mapped = sets
                    .iter()
                    .map(|digits| {
                        let mut subset: Subset =
                            digits.bytes().map(|d| phi[(d - b'0') as usize]).collect();
                        subset.sort();
                        subset
                    })
                    .collect();
                (phi[i], mapped)
            })
            .collect(),
    )
}

/// Uniform point in the ball of radius `radius` in `DIM` dimensions (`DIM + 2` Gaussians,
/// normalized, two dropped).
fn sample_ball<R: Rng + CryptoRng>(radius: f64, rng: &mut R) -> Vec<f64> {
    let mut g: Vec<f64> = (0..DIM + 2)
        .map(|_| {
            let (u1, u2): (f64, f64) = (rng.gen_range(f64::MIN_POSITIVE..1.0), rng.gen());
            (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
        })
        .collect();
    let norm = g.iter().map(|x| x * x).sum::<f64>().sqrt();
    g.truncate(DIM);
    g.iter_mut().for_each(|x| *x *= radius / norm);
    g
}

/// One repetition's secret state for a party.
struct Mask {
    x: Vec<f64>,
    r1: PolyVec,
    w: PolyVec,
}

/// A party's state between rounds. Single use: a mask must never answer two challenges.
pub struct Round1 {
    index: u8,
    masks: Vec<Mask>,
}

fn w_bytes(w: &[PolyVec]) -> Vec<u8> {
    w.iter()
        .flatten()
        .flatten()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

fn commitment(pk: &[u8], index: u8, w: &[PolyVec]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(
        &[b"cairn/mithril/commit/v1", pk, &[index], &w_bytes(w)],
        &mut out,
    );
    out
}

impl PartyKey {
    /// Round 1: sample `K` masks, compute `w = A r1 + r2` for each, publish a commitment.
    pub fn round1<R: Rng + CryptoRng>(&self, key: &GroupKey, rng: &mut R) -> (Round1, [u8; 32]) {
        let masks: Vec<Mask> = (0..key.params.reps)
            .map(|_| {
                let x = sample_ball(key.params.r_prime, rng);
                let round = |v: f64| red(v.round() as i64);
                let r1: PolyVec = (0..L)
                    .map(|i| std::array::from_fn(|j| round(NU * x[i * N + j])))
                    .collect();
                let r2: PolyVec = (0..K)
                    .map(|i| std::array::from_fn(|j| round(x[(L + i) * N + j])))
                    .collect();
                let w = vec_add(&mat_vec_coeff(&key.a_hat, &r1), &r2);
                Mask { x, r1, w }
            })
            .collect();
        let ws: Vec<PolyVec> = masks.iter().map(|m| m.w.clone()).collect();
        let cmt = commitment(&key.pk, self.index, &ws);
        (
            Round1 {
                index: self.index,
                masks,
            },
            cmt,
        )
    }

    /// Round 3: check everyone's commitments, derive each repetition's challenge, and answer
    /// with `z1 = c s1_part + r1` wherever the hyperball rejection test passes.
    pub fn round3(
        &self,
        key: &GroupKey,
        state: Round1,
        message: &[u8],
        commitments: &BTreeMap<u8, [u8; 32]>,
        revealed: &BTreeMap<u8, Vec<PolyVec>>,
    ) -> Option<Vec<Option<PolyVec>>> {
        let active: Vec<u8> = revealed.keys().copied().collect();
        if revealed
            .iter()
            .any(|(i, w)| commitments.get(i) != Some(&commitment(&key.pk, *i, w)))
        {
            return None;
        }
        let mine = recover_partition(&key.params, &active)?.remove(&self.index)?;
        let (mut s1, mut s2) = (vec_zero(L), vec_zero(K));
        for subset in &mine {
            let (a, b) = self.shares.get(subset)?;
            s1 = vec_add(&s1, a);
            s2 = vec_add(&s2, b);
        }
        let mu = message_representative(&key.tr, &[], message);
        let r_sq = key.params.r * key.params.r;
        let out = state
            .masks
            .iter()
            .enumerate()
            .map(|(rep, mask)| {
                let c = sample_in_ball(&challenge(&mu, revealed, rep));
                let (v1, v2) = (challenge_mul(&c, &s1), challenge_mul(&c, &s2));
                // Imbalanced hyperball rejection (the paper's HRej): accept iff
                // || (v1 / nu, v2) + x ||_2 <= r.
                let mut norm_sq = 0.0;
                for (i, coeff) in v1.iter().flatten().enumerate() {
                    let z = centered(*coeff) as f64 / NU + mask.x[i];
                    norm_sq += z * z;
                }
                for (i, coeff) in v2.iter().flatten().enumerate() {
                    let z = centered(*coeff) as f64 + mask.x[L * N + i];
                    norm_sq += z * z;
                }
                (norm_sq <= r_sq).then(|| vec_add(&v1, &mask.r1))
            })
            .collect();
        debug_assert_eq!(state.index, self.index);
        Some(out)
    }
}

impl Round1 {
    /// Round 2: reveal the commitments' openings.
    pub fn reveal(&self) -> Vec<PolyVec> {
        self.masks.iter().map(|m| m.w.clone()).collect()
    }
}

fn aggregate_w(revealed: &BTreeMap<u8, Vec<PolyVec>>, rep: usize) -> PolyVec {
    revealed
        .values()
        .fold(vec_zero(K), |acc, w| vec_add(&acc, &w[rep]))
}

fn challenge(
    mu: &[u8; 64],
    revealed: &BTreeMap<u8, Vec<PolyVec>>,
    rep: usize,
) -> [u8; C_TILDE_BYTES] {
    let mut c_tilde = [0u8; C_TILDE_BYTES];
    shake256(
        &[mu, &w1_encode(&high_bits(&aggregate_w(revealed, rep)))],
        &mut c_tilde,
    );
    c_tilde
}

/// Public combine (the paper's Figure 7): for the first repetition every party answered, sum
/// the responses, compute the hint from public values and check the ML-DSA bounds.
pub fn combine(
    key: &GroupKey,
    message: &[u8],
    revealed: &BTreeMap<u8, Vec<PolyVec>>,
    responses: &BTreeMap<u8, Vec<Option<PolyVec>>>,
) -> Option<[u8; SIGNATURE_BYTES]> {
    let mu = message_representative(&key.tr, &[], message);
    for rep in 0..key.params.reps {
        let Some(z1) = responses.values().try_fold(vec_zero(L), |acc, r| {
            Some(vec_add(&acc, r.get(rep)?.as_ref()?))
        }) else {
            continue;
        };
        let w = aggregate_w(revealed, rep);
        let c_tilde = challenge(&mu, revealed, rep);
        let c = sample_in_ball(&c_tilde);
        // approx = A z1 - 2^d c t1, the verifier's view of w; delta = w - approx.
        let t1_shifted: PolyVec = key
            .t1
            .iter()
            .map(|p| p.map(|x| red((x as i64) << D)))
            .collect();
        let approx = vec_sub(
            &mat_vec_coeff(&key.a_hat, &z1),
            &challenge_mul(&c, &t1_shifted),
        );
        let delta = vec_sub(&w, &approx);
        let hint: Hint = (0..K)
            .map(|i| std::array::from_fn(|j| decompose(approx[i][j]).0 != decompose(w[i][j]).0))
            .collect();
        if inf_norm(&z1) >= GAMMA1 - BETA
            || inf_norm(&delta) >= GAMMA2
            || hint_weight(&hint) > OMEGA
        {
            continue;
        }
        let signature = fips204::pack_signature(&c_tilde, &z1, &hint);
        if fips204::verify_standard(&key.pk, message, &signature) {
            return Some(signature);
        }
    }
    None
}

/// True when some repetition was answered by every party and its summed response does not
/// satisfy the signing equation, i.e. `w - (A z1 - 2^d c t1)` is far outside what honest
/// parties can produce. Honest executions fail only on the public bounds.
pub fn equation_fails(
    key: &GroupKey,
    message: &[u8],
    revealed: &BTreeMap<u8, Vec<PolyVec>>,
    responses: &BTreeMap<u8, Vec<Option<PolyVec>>>,
) -> bool {
    let mu = message_representative(&key.tr, &[], message);
    let t1_shifted: PolyVec = key
        .t1
        .iter()
        .map(|p| p.map(|x| red((x as i64) << D)))
        .collect();
    (0..key.params.reps).any(|rep| {
        let Some(z1) = responses.values().try_fold(vec_zero(L), |acc, r| {
            Some(vec_add(&acc, r.get(rep)?.as_ref()?))
        }) else {
            return false;
        };
        let c = sample_in_ball(&challenge(&mu, revealed, rep));
        let approx = vec_sub(
            &mat_vec_coeff(&key.a_hat, &z1),
            &challenge_mul(&c, &t1_shifted),
        );
        // delta = z2 - c t0: honestly below about 2^18; a wrong response makes it uniform.
        inf_norm(&vec_sub(&aggregate_w(revealed, rep), &approx)) > 4 * GAMMA2
    })
}

/// Which parties sent a response that cannot be an honest one.
///
/// Everything needed is public. For party `i` with partial key `t_i` (the sum of the `t_S` it
/// was assigned), `z2_i = w_i - (A z1_i - c t_i)` is the half of its response it did not send.
/// An honest party only answers when `||(z1_i / nu, z2_i)||_2 <= r`, so the same test, with
/// slack for rounding, can be run by anyone. A response that was altered turns `z2_i` into an
/// essentially uniform vector and fails by a wide margin.
///
/// Returns the indices that fail, or `None` if this key carries no per-subset public keys.
pub fn blame(
    key: &GroupKey,
    message: &[u8],
    revealed: &BTreeMap<u8, Vec<PolyVec>>,
    responses: &BTreeMap<u8, Vec<Option<PolyVec>>>,
) -> Option<Vec<u8>> {
    let active: Vec<u8> = revealed.keys().copied().collect();
    let partition = recover_partition(&key.params, &active)?;
    let mu = message_representative(&key.tr, &[], message);
    // Rounding moves each coordinate by at most a half (a twelfth for the scaled part).
    let bound = key.params.r + (DIM as f64).sqrt() / 2.0 + 1.0;
    let mut guilty = Vec::new();
    for (party, answers) in responses {
        let mut t_part = vec_zero(K);
        for subset in partition.get(party)? {
            t_part = vec_add(&t_part, key.subset_keys.get(subset)?);
        }
        let bad = answers.iter().enumerate().any(|(rep, answer)| {
            let Some(z1) = answer else { return false };
            let c = sample_in_ball(&challenge(&mu, revealed, rep));
            let approx = vec_sub(&mat_vec_coeff(&key.a_hat, z1), &challenge_mul(&c, &t_part));
            let z2 = vec_sub(&revealed[party][rep], &approx);
            let sq = |v: &PolyVec, scale: f64| -> f64 {
                v.iter()
                    .flatten()
                    .map(|x| (centered(*x) as f64 / scale).powi(2))
                    .sum()
            };
            sq(z1, NU) + sq(&z2, 1.0) > bound * bound
        });
        if bad {
            guilty.push(*party);
        }
    }
    Some(guilty)
}

/// What one in-process signature cost.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Protocol executions (each is three rounds) until one produced a signature.
    pub executions: u32,
    /// Bytes one party broadcast per execution (commitment, `K` openings, its responses),
    /// with `w` and `z1` at their packed sizes.
    pub bytes_per_party: usize,
}

/// Run the three rounds among `active` in this process until a signature comes out.
pub fn sign_local<R: Rng + CryptoRng>(
    key: &GroupKey,
    parties: &[PartyKey],
    active: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Option<([u8; SIGNATURE_BYTES], Stats)> {
    let signers: Vec<&PartyKey> = active
        .iter()
        .map(|i| parties.iter().find(|p| p.index == *i))
        .collect::<Option<_>>()?;
    let mut stats = Stats::default();
    for _ in 0..64 {
        stats.executions += 1;
        let (states, commitments): (Vec<Round1>, BTreeMap<u8, [u8; 32]>) = signers
            .iter()
            .map(|p| p.round1(key, rng))
            .map(|(s, c)| ((s.index, c), s))
            .map(|(ic, s)| (s, ic))
            .fold(
                (Vec::new(), BTreeMap::new()),
                |(mut states, mut cmts), (s, (i, c))| {
                    states.push(s);
                    cmts.insert(i, c);
                    (states, cmts)
                },
            );
        let revealed: BTreeMap<u8, Vec<PolyVec>> =
            states.iter().map(|s| (s.index, s.reveal())).collect();
        let mut responses = BTreeMap::new();
        for (party, state) in signers.iter().zip(states) {
            responses.insert(
                party.index,
                party.round3(key, state, message, &commitments, &revealed)?,
            );
        }
        let answered = responses
            .values()
            .next()
            .map_or(0, |r: &Vec<Option<PolyVec>>| r.iter().flatten().count());
        // 23 bits per coefficient of w, 20 per coefficient of z1 (as in the signature encoding).
        stats.bytes_per_party = 32 + key.params.reps * K * N * 23 / 8 + answered * L * N * 20 / 8;
        if let Some(signature) = combine(key, message, &revealed, &responses) {
            return Some((signature, stats));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// The sharing patterns hard-coded in the authors' reference implementation
    /// (`recoverShare` in thmldsa65/internal/dilithium.go), as bitmasks over party indices.
    /// Same tables and same relabelling means a party uses the same subset secrets there
    /// and here for any active set.
    #[test]
    fn partition_tables_match_reference_implementation() {
        let reference: &[(usize, usize, &[&[u8]])] = &[
            (2, 3, &[&[3, 5], &[6]]),
            (2, 4, &[&[11, 13], &[7, 14]]),
            (3, 4, &[&[3, 9], &[6, 10], &[12, 5]]),
            (2, 5, &[&[27, 29, 23], &[30, 15]]),
            (3, 5, &[&[25, 11, 19, 13], &[7, 14, 22, 26], &[28, 21]]),
            (4, 5, &[&[3, 9, 17], &[6, 10, 18], &[12, 5, 20], &[24]]),
            (2, 6, &[&[61, 47, 55], &[62, 31, 59]]),
            (
                3,
                6,
                &[
                    &[27, 23, 43, 57, 39],
                    &[51, 58, 46, 30, 54],
                    &[45, 53, 29, 15, 60],
                ],
            ),
            (
                4,
                6,
                &[
                    &[19, 13, 35, 7, 49],
                    &[42, 26, 38, 50, 22],
                    &[52, 21, 44, 28, 37],
                    &[25, 11, 14, 56, 41],
                ],
            ),
            (
                5,
                6,
                &[
                    &[3, 5, 33],
                    &[6, 10, 34],
                    &[12, 20, 36],
                    &[9, 24, 40],
                    &[48, 17, 18],
                ],
            ),
        ];
        for (t, n, masks) in reference {
            let ours = ideal_sharing(*t, *n).unwrap();
            assert_eq!(ours.len(), masks.len(), "{t}-of-{n}");
            for (row, want) in ours.iter().zip(masks.iter()) {
                let mut got: Vec<u8> = row
                    .iter()
                    .map(|d| d.bytes().fold(0u8, |m, b| m | 1 << (b - b'0')))
                    .collect();
                let mut want = want.to_vec();
                got.sort();
                want.sort();
                assert_eq!(got, want, "{t}-of-{n}");
            }
        }
    }

    /// A uniform point in a d-ball of radius r has (|x|/r)^d uniform on [0,1]. Checks the
    /// "d+2 Gaussians, drop two" sampler against that, and that no sample leaves the ball.
    #[test]
    fn ball_sampler_is_uniform_in_radius() {
        let (r, runs) = (500_000.0f64, 300);
        let mut sum = 0.0;
        for _ in 0..runs {
            let x = sample_ball(r, &mut OsRng);
            let norm = x.iter().map(|v| v * v).sum::<f64>().sqrt();
            assert!(norm <= r);
            sum += (norm / r).powi(DIM as i32);
        }
        let mean = sum / runs as f64;
        assert!((mean - 0.5).abs() < 0.1, "mean {mean}");
    }

    #[test]
    fn partitions_cover_every_secret_exactly_once() {
        for (t, n) in [
            (2, 2),
            (2, 3),
            (3, 3),
            (2, 4),
            (3, 4),
            (4, 4),
            (2, 5),
            (3, 5),
            (4, 5),
            (5, 5),
            (2, 6),
            (3, 6),
            (4, 6),
            (5, 6),
            (6, 6),
        ] {
            let params = params_65(t, n).unwrap();
            for active in subsets(n, t) {
                let part = recover_partition(&params, &active).unwrap();
                let mut seen: Vec<Subset> = part.values().flatten().cloned().collect();
                seen.sort();
                assert_eq!(
                    seen,
                    {
                        let mut all = subsets(n, n - t + 1);
                        all.sort();
                        all
                    },
                    "{t}-of-{n} {active:?}"
                );
                assert!(part
                    .iter()
                    .all(|(i, sets)| sets.iter().all(|s| s.contains(i))));
            }
        }
    }

    #[test]
    fn fewer_than_t_parties_miss_a_secret() {
        let (_, parties) = keygen(3, 4, &mut OsRng).unwrap();
        for pair in subsets(4, 2) {
            let held: std::collections::BTreeSet<&Subset> = pair
                .iter()
                .flat_map(|i| parties[*i as usize].shares.keys())
                .collect();
            assert!(
                held.len() < subsets(4, 2).len(),
                "{pair:?} hold every secret"
            );
        }
    }

    #[test]
    fn three_rounds_produce_standard_signatures() {
        for (t, n) in [(2, 3), (3, 4)] {
            let (key, parties) = keygen(t, n, &mut OsRng).unwrap();
            for active in subsets(n, t) {
                let msg = format!("mithril {t}-of-{n} {active:?}").into_bytes();
                let (signature, stats) =
                    sign_local(&key, &parties, &active, &msg, &mut OsRng).expect("signs");
                assert!(fips204::verify_standard(&key.pk, &msg, &signature));
                assert!(!fips204::verify_standard(&key.pk, b"other", &signature));
                assert!(stats.executions <= 16, "{stats:?}");
            }
        }
    }

    #[test]
    fn wire_packing_round_trips() {
        let (key, parties) = keygen(2, 3, &mut OsRng).unwrap();
        let (state, _) = parties[0].round1(&key, &mut OsRng);
        let w = &state.reveal()[0];
        let packed = w_to_wire(w);
        assert_eq!(packed.len(), K * N * 23 / 8);
        assert_eq!(&w_from_wire(&packed).unwrap(), w);
        assert!(w_from_wire(&packed[1..]).is_none());
        let z: PolyVec = (0..L)
            .map(|i| std::array::from_fn(|j| ((i * 7919 + j * 104729) % 8_380_417) as i32))
            .collect();
        assert_eq!(z_from_wire(&z_to_wire(&z)).unwrap(), z);
    }

    #[test]
    fn a_wrong_response_is_pinned_on_its_sender() {
        let (key, parties) = keygen(3, 4, &mut OsRng).unwrap();
        let active = [0u8, 1, 3];
        let msg = b"blame";
        let (mut states, mut commitments) = (Vec::new(), BTreeMap::new());
        for i in active {
            let (state, cmt) = parties[i as usize].round1(&key, &mut OsRng);
            commitments.insert(i, cmt);
            states.push(state);
        }
        let revealed: BTreeMap<u8, Vec<PolyVec>> =
            states.iter().map(|s| (s.index, s.reveal())).collect();
        let mut responses = BTreeMap::new();
        for state in states {
            let i = state.index;
            responses.insert(
                i,
                parties[i as usize]
                    .round3(&key, state, msg, &commitments, &revealed)
                    .unwrap(),
            );
        }
        // Honest responses: nobody is blamed, whether or not the execution yields a signature.
        assert_eq!(blame(&key, msg, &revealed, &responses), Some(vec![]));
        // Party 1 alters one coefficient of one response.
        let altered = responses.get_mut(&1).unwrap().iter_mut().flatten().next();
        if let Some(z) = altered {
            z[0][0] = (z[0][0] + 1) % fips204::Q;
            assert_eq!(blame(&key, msg, &revealed, &responses), Some(vec![1]));
        }
        // The keys survive serialization.
        let restored = GroupKey::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!(restored.subset_keys, key.subset_keys);
        assert_eq!(restored.pk, key.pk);
    }

    #[test]
    fn a_wrong_opening_is_refused() {
        let (key, parties) = keygen(2, 3, &mut OsRng).unwrap();
        let (s0, c0) = parties[0].round1(&key, &mut OsRng);
        let (s1, c1) = parties[1].round1(&key, &mut OsRng);
        let commitments: BTreeMap<u8, [u8; 32]> = [(0, c0), (1, c1)].into();
        let mut revealed: BTreeMap<u8, Vec<PolyVec>> = [(0, s0.reveal()), (1, s1.reveal())].into();
        revealed.get_mut(&1).unwrap()[0][0][0] ^= 1;
        assert!(parties[0]
            .round3(&key, s0, b"m", &commitments, &revealed)
            .is_none());
    }
}
