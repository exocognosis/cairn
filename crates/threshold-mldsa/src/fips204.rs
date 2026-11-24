//! FIPS 204 ML-DSA-65 internals (parameters, NTT, sampling, rounding, encodings).
//!
//! Written against the FIPS 204 algorithm numbers and validated byte-for-byte against the
//! RustCrypto `ml-dsa` crate (public key and deterministic signature equality, see tests).
//! Polynomials hold coefficients in `[0, Q)`. Arithmetic is plain `i64` modular reduction:
//! clarity over speed, and not constant time (see ARCHITECTURE.md, "Side channels").

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};
use std::sync::OnceLock;

pub const Q: i32 = 8_380_417;
pub const N: usize = 256;
pub const D: u32 = 13;
pub const K: usize = 6;
pub const L: usize = 5;
pub const TAU: usize = 49;
pub const BETA: i32 = 196;
pub const GAMMA1: i32 = 1 << 19;
pub const GAMMA2: i32 = (Q - 1) / 32;
pub const OMEGA: usize = 55;
pub const C_TILDE_BYTES: usize = 48;
pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;

pub type Poly = [i32; N];
pub type PolyVec = Vec<Poly>;
/// `K x L` matrix in the NTT domain.
pub type MatrixHat = Vec<Vec<Poly>>;

#[inline]
pub fn red(x: i64) -> i32 {
    x.rem_euclid(Q as i64) as i32
}

#[inline]
pub fn fq_mul(a: i32, b: i32) -> i32 {
    red(a as i64 * b as i64)
}

pub fn fq_pow(mut b: i32, mut e: u32) -> i32 {
    let mut acc = 1;
    while e > 0 {
        if e & 1 == 1 {
            acc = fq_mul(acc, b);
        }
        b = fq_mul(b, b);
        e >>= 1;
    }
    acc
}

pub fn fq_inv(a: i32) -> i32 {
    fq_pow(a, Q as u32 - 2)
}

/// Representative in `(-Q/2, Q/2]`.
#[inline]
pub fn centered(x: i32) -> i32 {
    if x > Q / 2 {
        x - Q
    } else {
        x
    }
}

pub fn inf_norm(v: &[Poly]) -> i32 {
    v.iter()
        .flat_map(|p| p.iter())
        .map(|&c| centered(c).abs())
        .max()
        .unwrap_or(0)
}

fn zetas() -> &'static [i32; N] {
    static Z: OnceLock<[i32; N]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [0i32; N];
        for (k, slot) in z.iter_mut().enumerate() {
            *slot = fq_pow(1753, (k as u8).reverse_bits() as u32);
        }
        z
    })
}

/// FIPS 204 Algorithm 41.
pub fn ntt(w: &mut Poly) {
    let z = zetas();
    let (mut m, mut len) = (0usize, 128usize);
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            for j in start..start + len {
                let t = fq_mul(z[m], w[j + len]);
                w[j + len] = red(w[j] as i64 - t as i64);
                w[j] = red(w[j] as i64 + t as i64);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// FIPS 204 Algorithm 42.
pub fn inv_ntt(w: &mut Poly) {
    let z = zetas();
    let (mut m, mut len) = (N, 1usize);
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            let zeta = Q - z[m];
            for j in start..start + len {
                let t = w[j];
                w[j] = red(t as i64 + w[j + len] as i64);
                w[j + len] = fq_mul(zeta, red(t as i64 - w[j + len] as i64));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in w.iter_mut() {
        *c = fq_mul(*c, 8_347_681);
    }
}

pub fn vec_ntt(v: &[Poly]) -> PolyVec {
    v.iter()
        .map(|p| {
            let mut p = *p;
            ntt(&mut p);
            p
        })
        .collect()
}

pub fn vec_inv_ntt(v: &[Poly]) -> PolyVec {
    v.iter()
        .map(|p| {
            let mut p = *p;
            inv_ntt(&mut p);
            p
        })
        .collect()
}

pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    std::array::from_fn(|i| red(a[i] as i64 + b[i] as i64))
}

pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    std::array::from_fn(|i| red(a[i] as i64 - b[i] as i64))
}

pub fn poly_pointwise(a: &Poly, b: &Poly) -> Poly {
    std::array::from_fn(|i| fq_mul(a[i], b[i]))
}

pub fn poly_scale(a: &Poly, s: i32) -> Poly {
    std::array::from_fn(|i| fq_mul(a[i], s))
}

pub fn vec_add(a: &[Poly], b: &[Poly]) -> PolyVec {
    a.iter().zip(b).map(|(x, y)| poly_add(x, y)).collect()
}

pub fn vec_sub(a: &[Poly], b: &[Poly]) -> PolyVec {
    a.iter().zip(b).map(|(x, y)| poly_sub(x, y)).collect()
}

pub fn vec_scale(a: &[Poly], s: i32) -> PolyVec {
    a.iter().map(|x| poly_scale(x, s)).collect()
}

pub fn vec_zero(len: usize) -> PolyVec {
    vec![[0i32; N]; len]
}

/// `A_hat * v_hat` (both in the NTT domain).
pub fn mat_vec(a_hat: &MatrixHat, v_hat: &[Poly]) -> PolyVec {
    a_hat
        .iter()
        .map(|row| {
            row.iter()
                .zip(v_hat)
                .fold([0i32; N], |acc, (a, v)| poly_add(&acc, &poly_pointwise(a, v)))
        })
        .collect()
}

/// `A * v` for `v` in the coefficient domain.
pub fn mat_vec_coeff(a_hat: &MatrixHat, v: &[Poly]) -> PolyVec {
    vec_inv_ntt(&mat_vec(a_hat, &vec_ntt(v)))
}

/// `c * v` for a coefficient-domain `c` and `v`.
pub fn challenge_mul(c: &Poly, v: &[Poly]) -> PolyVec {
    let mut c_hat = *c;
    ntt(&mut c_hat);
    vec_inv_ntt(
        &vec_ntt(v)
            .iter()
            .map(|p| poly_pointwise(&c_hat, p))
            .collect::<Vec<_>>(),
    )
}

pub fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

/// FIPS 204 Algorithm 32 (ExpandA), output in the NTT domain.
pub fn expand_a(rho: &[u8; 32]) -> MatrixHat {
    (0..K as u8)
        .map(|r| {
            (0..L as u8)
                .map(|s| {
                    let mut h = Shake128::default();
                    h.update(rho);
                    h.update(&[s, r]);
                    let mut xof = h.finalize_xof();
                    let mut p = [0i32; N];
                    let mut j = 0;
                    while j < N {
                        let mut b = [0u8; 3];
                        xof.read(&mut b);
                        let z = b[0] as i32 | (b[1] as i32) << 8 | ((b[2] & 0x7f) as i32) << 16;
                        if z < Q {
                            p[j] = z;
                            j += 1;
                        }
                    }
                    p
                })
                .collect()
        })
        .collect()
}

fn rej_bounded_poly(seed: &[u8; 64], nonce: u16) -> Poly {
    let mut h = Shake256::default();
    h.update(seed);
    h.update(&nonce.to_le_bytes());
    let mut xof = h.finalize_xof();
    let mut p = [0i32; N];
    let mut j = 0;
    while j < N {
        let mut b = [0u8; 1];
        xof.read(&mut b);
        for z in [b[0] & 0x0f, b[0] >> 4] {
            if z < 9 && j < N {
                p[j] = red(4 - z as i64);
                j += 1;
            }
        }
    }
    p
}

/// FIPS 204 Algorithm 33 (ExpandS), eta = 4.
pub fn expand_s(rho_prime: &[u8; 64]) -> (PolyVec, PolyVec) {
    let s1 = (0..L as u16).map(|r| rej_bounded_poly(rho_prime, r)).collect();
    let s2 = (0..K as u16)
        .map(|r| rej_bounded_poly(rho_prime, r + L as u16))
        .collect();
    (s1, s2)
}

/// FIPS 204 Algorithm 34 (ExpandMask), gamma1 = 2^19. This is the exact deterministic mask.
pub fn expand_mask(rho_pp: &[u8; 64], kappa: u16) -> PolyVec {
    (0..L as u16)
        .map(|r| {
            let mut v = [0u8; 640];
            shake256(&[rho_pp, &(kappa + r).to_le_bytes()], &mut v);
            let mut p = [0i32; N];
            for (i, c) in p.iter_mut().enumerate() {
                let bit = i * 20;
                let raw = u32::from_le_bytes([
                    v[bit / 8],
                    v[bit / 8 + 1],
                    v[bit / 8 + 2],
                    if bit / 8 + 3 < 640 { v[bit / 8 + 3] } else { 0 },
                ]);
                let val = (raw >> (bit % 8)) & 0xf_ffff;
                *c = red(GAMMA1 as i64 - val as i64);
            }
            p
        })
        .collect()
}

/// FIPS 204 Algorithm 29 (SampleInBall).
pub fn sample_in_ball(c_tilde: &[u8; C_TILDE_BYTES]) -> Poly {
    let mut h = Shake256::default();
    h.update(c_tilde);
    let mut xof = h.finalize_xof();
    let mut s = [0u8; 8];
    xof.read(&mut s);
    let signs = u64::from_le_bytes(s);
    let mut c = [0i32; N];
    for i in N - TAU..N {
        let j = loop {
            let mut b = [0u8; 1];
            xof.read(&mut b);
            if b[0] as usize <= i {
                break b[0] as usize;
            }
        };
        c[i] = c[j];
        c[j] = if (signs >> (i + TAU - N)) & 1 == 1 { Q - 1 } else { 1 };
    }
    c
}

/// FIPS 204 Algorithm 35: `r -> (r1, r0)` with `r = r1 * 2^d + r0`.
pub fn power2round(r: i32) -> (i32, i32) {
    let r0 = {
        let m = r & ((1 << D) - 1);
        if m > 1 << (D - 1) {
            m - (1 << D)
        } else {
            m
        }
    };
    ((r - r0) >> D, r0)
}

/// FIPS 204 Algorithm 36: `r -> (r1, r0)`, `r0` centered.
pub fn decompose(r: i32) -> (i32, i32) {
    let mut r0 = r % (2 * GAMMA2);
    if r0 > GAMMA2 {
        r0 -= 2 * GAMMA2;
    }
    if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / (2 * GAMMA2), r0)
    }
}

pub fn high_bits(v: &[Poly]) -> PolyVec {
    v.iter().map(|p| p.map(|c| decompose(c).0)).collect()
}

/// `LowBits`, returned mod Q (use [`inf_norm`] for the centered norm).
pub fn low_bits(v: &[Poly]) -> PolyVec {
    v.iter()
        .map(|p| p.map(|c| red(decompose(c).1 as i64)))
        .collect()
}

fn pack_bits(vals: impl Iterator<Item = u32>, bits: u32, out: &mut Vec<u8>) {
    let (mut acc, mut n) = (0u64, 0u32);
    for v in vals {
        acc |= (v as u64) << n;
        n += bits;
        while n >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            n -= 8;
        }
    }
    debug_assert_eq!(n, 0);
}

/// FIPS 204 Algorithm 28 (w1Encode): 4 bits per coefficient.
pub fn w1_encode(w1: &[Poly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * 128);
    pack_bits(w1.iter().flat_map(|p| p.iter().map(|&c| c as u32)), 4, &mut out);
    out
}

/// Hint vector: `h[i][j]` set where a carry correction is needed.
pub type Hint = Vec<[bool; N]>;

pub fn hint_weight(h: &Hint) -> usize {
    h.iter().flat_map(|p| p.iter()).filter(|&&b| b).count()
}

/// FIPS 204 Algorithm 26 (sigEncode).
pub fn pack_signature(c_tilde: &[u8; C_TILDE_BYTES], z: &[Poly], h: &Hint) -> [u8; SIGNATURE_BYTES] {
    let mut out = Vec::with_capacity(SIGNATURE_BYTES);
    out.extend_from_slice(c_tilde);
    pack_bits(
        z.iter()
            .flat_map(|p| p.iter().map(|&c| (GAMMA1 - centered(c)) as u32)),
        20,
        &mut out,
    );
    let mut y = [0u8; OMEGA + K];
    let mut index = 0;
    for (i, p) in h.iter().enumerate() {
        for (j, &bit) in p.iter().enumerate() {
            if bit {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[OMEGA + i] = index as u8;
    }
    out.extend_from_slice(&y);
    out.try_into().expect("signature length")
}

/// Expanded ML-DSA-65 key material (FIPS 204 Algorithm 6, KeyGen_internal).
pub struct ExpandedKey {
    pub rho: [u8; 32],
    pub k: [u8; 32],
    pub tr: [u8; 64],
    pub s1: PolyVec,
    pub s2: PolyVec,
    pub t0: PolyVec,
    pub pk: [u8; PUBLIC_KEY_BYTES],
}

pub fn keygen_internal(xi: &[u8; 32]) -> ExpandedKey {
    let mut seed = [0u8; 128];
    shake256(&[xi, &[K as u8, L as u8]], &mut seed);
    let rho: [u8; 32] = seed[..32].try_into().unwrap();
    let rho_prime: [u8; 64] = seed[32..96].try_into().unwrap();
    let k: [u8; 32] = seed[96..].try_into().unwrap();
    let (s1, s2) = expand_s(&rho_prime);
    let t = vec_add(&mat_vec_coeff(&expand_a(&rho), &s1), &s2);
    let mut t1 = vec_zero(K);
    let mut t0 = vec_zero(K);
    for i in 0..K {
        for j in 0..N {
            let (hi, lo) = power2round(t[i][j]);
            t1[i][j] = hi;
            t0[i][j] = red(lo as i64);
        }
    }
    let mut pk = Vec::with_capacity(PUBLIC_KEY_BYTES);
    pk.extend_from_slice(&rho);
    pack_bits(t1.iter().flat_map(|p| p.iter().map(|&c| c as u32)), 10, &mut pk);
    let pk: [u8; PUBLIC_KEY_BYTES] = pk.try_into().expect("public key length");
    let mut tr = [0u8; 64];
    shake256(&[&pk], &mut tr);
    ExpandedKey { rho, k, tr, s1, s2, t0, pk }
}

/// Message representative `mu = H(tr || 0 || len(ctx) || ctx || M)` for pure ML-DSA.Sign.
pub fn message_representative(tr: &[u8; 64], ctx: &[u8], message: &[u8]) -> [u8; 64] {
    assert!(ctx.len() <= 255, "context longer than 255 bytes");
    let mut mu = [0u8; 64];
    shake256(&[tr, &[0, ctx.len() as u8], ctx, message], &mut mu);
    mu
}

/// `rho'' = H(K || rnd || mu)`; `rnd` is all zero for the deterministic variant.
pub fn mask_seed(k: &[u8; 32], rnd: &[u8; 32], mu: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    shake256(&[k, rnd, mu], &mut out);
    out
}

/// First half of one signing attempt: `w = A y`, `c~ = H(mu || w1Encode(HighBits(w)))`.
pub fn commit_mask(a_hat: &MatrixHat, y: &[Poly], mu: &[u8; 64]) -> (PolyVec, [u8; C_TILDE_BYTES]) {
    let w = mat_vec_coeff(a_hat, y);
    let mut c_tilde = [0u8; C_TILDE_BYTES];
    shake256(&[mu, &w1_encode(&high_bits(&w))], &mut c_tilde);
    (w, c_tilde)
}

/// Why an attempt was rejected (kept internal to the engine boundary; never put on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    ZNorm,
    LowBitsNorm,
    Ct0Norm,
    HintWeight,
}

/// Second half of one attempt: the four FIPS 204 abort conditions and the hint.
/// `z = y + c s1`, `r = w - c s2`, `ct0 = c t0`, all mod Q.
pub fn finish_attempt(z: &[Poly], r: &[Poly], ct0: &[Poly]) -> Result<Hint, Rejection> {
    if inf_norm(z) >= GAMMA1 - BETA {
        return Err(Rejection::ZNorm);
    }
    if inf_norm(&low_bits(r)) >= GAMMA2 - BETA {
        return Err(Rejection::LowBitsNorm);
    }
    if inf_norm(ct0) >= GAMMA2 {
        return Err(Rejection::Ct0Norm);
    }
    // MakeHint(-ct0, w - cs2 + ct0): HighBits(r) != HighBits(r + ct0) ... with z = -ct0 added back.
    let with_ct0 = vec_add(r, ct0);
    let h: Hint = (0..K)
        .map(|i| std::array::from_fn(|j| decompose(r[i][j]).0 != decompose(with_ct0[i][j]).0))
        .collect();
    if hint_weight(&h) > OMEGA {
        return Err(Rejection::HintWeight);
    }
    Ok(h)
}

/// Single-key reference signer (deterministic variant). Returns the signature and the number of
/// rejected attempts. Used as the oracle the threshold protocol must match byte-for-byte.
pub fn sign_reference(key: &ExpandedKey, message: &[u8]) -> ([u8; SIGNATURE_BYTES], u32) {
    let a_hat = expand_a(&key.rho);
    let mu = message_representative(&key.tr, &[], message);
    let rho_pp = mask_seed(&key.k, &[0u8; 32], &mu);
    let mut attempt = 0u32;
    loop {
        let y = expand_mask(&rho_pp, (attempt as usize * L) as u16);
        let (w, c_tilde) = commit_mask(&a_hat, &y, &mu);
        let c = sample_in_ball(&c_tilde);
        let z = vec_add(&y, &challenge_mul(&c, &key.s1));
        let r = vec_sub(&w, &challenge_mul(&c, &key.s2));
        let ct0 = challenge_mul(&c, &key.t0);
        if let Ok(h) = finish_attempt(&z, &r, &ct0) {
            return (pack_signature(&c_tilde, &z, &h), attempt);
        }
        attempt += 1;
    }
}

/// Off-the-shelf FIPS 204 verification (RustCrypto `ml-dsa`), empty context.
pub fn verify_standard(pk: &[u8; PUBLIC_KEY_BYTES], message: &[u8], sig: &[u8; SIGNATURE_BYTES]) -> bool {
    use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
    let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(pk.as_slice()) else {
        return false;
    };
    let Ok(sig) = Signature::<MlDsa65>::try_from(sig.as_slice()) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&enc).verify_with_context(message, &[], &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{ExpandedSigningKey, MlDsa65};

    #[test]
    fn ntt_round_trip() {
        let mut p: Poly = std::array::from_fn(|i| (i as i32 * 7919) % Q);
        let orig = p;
        ntt(&mut p);
        inv_ntt(&mut p);
        assert_eq!(p, orig);
    }

    #[test]
    fn decompose_is_exact_on_boundaries() {
        for r in [0, 1, GAMMA2, GAMMA2 + 1, Q - 1, Q - GAMMA2, 2 * GAMMA2] {
            let (r1, r0) = decompose(r);
            assert_eq!(red(r1 as i64 * 2 * GAMMA2 as i64 + r0 as i64), r);
            assert!(r0.abs() <= GAMMA2 && (0..16).contains(&r1));
        }
    }

    #[test]
    fn keygen_and_deterministic_signature_match_rustcrypto() {
        for s in 0u8..4 {
            let seed = [s.wrapping_mul(37).wrapping_add(1); 32];
            let ours = keygen_internal(&seed);
            let theirs = ExpandedSigningKey::<MlDsa65>::from_seed(&seed.into());
            assert_eq!(ours.pk.as_slice(), theirs.verifying_key().encode().as_slice());
            let msg = [b"cairn reference vector ".as_slice(), &[s]].concat();
            let (sig, _) = sign_reference(&ours, &msg);
            let expect = theirs.sign_deterministic(&msg, &[]).unwrap();
            assert_eq!(sig.as_slice(), expect.encode().as_slice());
            assert!(verify_standard(&ours.pk, &msg, &sig));
        }
    }
}
