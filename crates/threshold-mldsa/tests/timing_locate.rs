//! Where the response round's share-dependent time comes from: the multiplication of the
//! challenge by the share, timed alone. A measurement, not a pass/fail test; it prints.
//!
//!   cargo test --release -p threshold-mldsa --test timing_locate -- --ignored --nocapture
//!
//! Three comparisons: an all-zero share against one at the bound (the two extremes the
//! response-round test uses), two different shares with random small coefficients (what two
//! real shares look like), and the same share against itself (the method's own floor).

use rand::{rngs::OsRng, Rng};
use std::time::Instant;
use threshold_mldsa::fips204::{challenge_mul, Poly, PolyVec, N, Q};

fn welch(a: &[f64], b: &[f64]) -> (f64, f64, f64) {
    let stats = |v: &[f64]| {
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
        (mean, var, v.len() as f64)
    };
    let ((ma, va, na), (mb, vb, nb)) = (stats(a), stats(b));
    (ma, mb, (ma - mb) / (va / na + vb / nb).sqrt())
}

fn compare(what: &str, c: &Poly, vecs: [&PolyVec; 2]) {
    let mut times: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
    for _ in 0..200_000 {
        let class = OsRng.gen_range(0..2usize);
        let start = Instant::now();
        let out = challenge_mul(c, vecs[class]);
        let elapsed = start.elapsed().as_nanos() as f64;
        std::hint::black_box(out);
        times[class].push(elapsed);
    }
    // Drop the slowest 5% of each class: interrupts.
    for t in times.iter_mut() {
        t.sort_by(|a, b| a.partial_cmp(b).unwrap());
        t.truncate(t.len() * 95 / 100);
    }
    let (a, b, t) = welch(&times[0], &times[1]);
    println!("{what}: {a:.1} ns against {b:.1} ns, t = {t:.2}");
}

#[test]
#[ignore = "timing measurement"]
fn share_multiplication_time_by_input() {
    threshold_mldsa::ct::harden_thread();
    let small = || -> PolyVec {
        (0..5)
            .map(|_| std::array::from_fn(|_| (OsRng.gen_range(-4i32..=4)).rem_euclid(Q)))
            .collect()
    };
    let zero: PolyVec = (0..5).map(|_| std::array::from_fn(|_| 0)).collect();
    let bound: PolyVec = (0..5)
        .map(|_| std::array::from_fn(|j| if j % 2 == 0 { 4 } else { Q - 4 }))
        .collect();
    let (one, other) = (small(), small());
    let copy = one.clone();
    let mut c: Poly = [0; N];
    for j in 0..49 {
        c[j * 5] = if j % 2 == 0 { 1 } else { Q - 1 };
    }
    compare("zero share against bound share", &c, [&zero, &bound]);
    compare("two random small shares", &c, [&one, &other]);
    compare("one share against its copy", &c, [&one, &copy]);
}
