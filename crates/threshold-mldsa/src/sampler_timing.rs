//! Does the time of the sampler's arithmetic depend on its operands, in ways a comparison of
//! average times would miss? A measurement, not a pass/fail test; it prints.
//!
//!   cargo test --release -p threshold-mldsa sampler_timing -- --ignored --nocapture
//!
//! `tests/timing.rs` compares the mean time of a whole mask round between two classes of
//! masks. A reviewer pointed out that a divide or square root whose time depends on its
//! operands could leave the mean alone and change the spread, or matter only for operands a
//! random mask rarely produces. So each elementary step is timed here by itself, on operands
//! chosen to be the easy cases for a hardware divider or square root (powers of two, exact
//! squares, values at the ends of the range) against random ones, and compared two ways:
//! mean against mean, and spread against spread (the dudect second-order test: a t-test on
//! the squared distance from the common mean). Random against random is the method's floor.

use super::{ball_from_uniforms, uniform_pair, PAIRS};
use crate::dd::Dd;
use rand::{rngs::OsRng, Rng};
use std::time::Instant;

/// Operations per timed batch: one is far below the clock's resolution.
const BATCH: usize = 256;
const BATCHES: usize = 64;

fn welch(a: &[f64], b: &[f64]) -> f64 {
    let stats = |v: &[f64]| {
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
        (mean, var, v.len() as f64)
    };
    let ((ma, va, na), (mb, vb, nb)) = (stats(a), stats(b));
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// First- and second-order t for two classes of timings, after dropping everything above the
/// pooled 95th percentile (interrupts).
fn orders(times: &[Vec<f64>; 2]) -> (f64, f64, f64, f64) {
    let mut pooled: Vec<f64> = times.iter().flatten().copied().collect();
    pooled.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let cut = pooled[pooled.len() * 95 / 100];
    let kept: Vec<Vec<f64>> = times
        .iter()
        .map(|t| t.iter().copied().filter(|x| *x <= cut).collect())
        .collect();
    let all = kept.iter().flatten().count() as f64;
    let mean = kept.iter().flatten().sum::<f64>() / all;
    let squared: Vec<Vec<f64>> = kept
        .iter()
        .map(|t| t.iter().map(|x| (x - mean).powi(2)).collect())
        .collect();
    let avg = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64 / BATCH as f64;
    (
        avg(&kept[0]),
        avg(&kept[1]),
        welch(&kept[0], &kept[1]),
        welch(&squared[0], &squared[1]),
    )
}

/// Time `op` over batches of operands from two classes, picked at random per measurement.
fn compare<I: Copy, O>(what: &str, classes: [&dyn Fn() -> I; 2], op: impl Fn(I) -> O) -> f64 {
    let pools: Vec<Vec<Vec<I>>> = classes
        .iter()
        .map(|make| {
            (0..BATCHES)
                .map(|_| (0..BATCH).map(|_| make()).collect())
                .collect()
        })
        .collect();
    let mut times: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
    for _ in 0..60_000 {
        let class = OsRng.gen_range(0..2usize);
        let batch = &pools[class][OsRng.gen_range(0..BATCHES)];
        let start = Instant::now();
        for input in batch {
            std::hint::black_box(op(std::hint::black_box(*input)));
        }
        times[class].push(start.elapsed().as_nanos() as f64);
    }
    let (a, b, first, second) = orders(&times);
    println!(
        "{what}: {a:.2} ns against {b:.2} ns per call, t = {first:.2}, spread t = {second:.2}"
    );
    first.abs().max(second.abs())
}

fn random() -> Dd {
    uniform_pair(&mut OsRng).0
}

#[test]
#[ignore = "timing measurement"]
fn sampler_step_times_by_operand() {
    crate::ct::harden_thread();
    let pick = |values: &'static [f64]| move || Dd(values[OsRng.gen_range(0..values.len())], 0.0);
    // The operands a mask really produces, for the divide and the square root: a norm near
    // sqrt(DIM + 2), a radial value -2 ln u.
    let norm = || Dd(35.0 + 3.0 * random().0, random().1 * 1e-16);
    let radial = || random().ln().mul_f64(-2.0);

    println!("floor (random against random):");
    compare("  ln", [&random, &random], |u: Dd| u.ln());
    compare("  sqrt", [&radial, &radial], |x: Dd| x.sqrt());
    compare("  divide", [&norm, &norm], |x: Dd| Dd(1000.0, 0.0).div(x));
    compare("  cos and sin", [&random, &random], |u: Dd| {
        u.cos_sin_turn()
    });

    println!("easy operands against random ones:");
    compare(
        "  ln of a power of two",
        [&pick(&[0.5, 0.25, 0.125, 1.0 / 1024.0]), &random],
        |u: Dd| u.ln(),
    );
    compare(
        "  ln at the ends of the range",
        [
            &pick(&[1.1102230246251565e-16, 0.9999999999999999]),
            &random,
        ],
        |u: Dd| u.ln(),
    );
    compare(
        "  sqrt of an exact square",
        [&pick(&[1.0, 4.0, 9.0, 16.0, 0.25]), &radial],
        |x: Dd| x.sqrt(),
    );
    compare(
        "  divide by a power of two",
        [&pick(&[32.0, 64.0, 16.0]), &norm],
        |x: Dd| Dd(1000.0, 0.0).div(x),
    );
    compare(
        "  divide a zero",
        [&|| (Dd::ZERO, norm()), &|| (random(), norm())],
        |(a, b): (Dd, Dd)| a.div(b),
    );
    compare(
        "  cos and sin of a quarter turn",
        [&pick(&[0.0, 0.25, 0.5, 0.75]), &random],
        |u: Dd| u.cos_sin_turn(),
    );
    compare(
        "  multiply by zero",
        [&|| (Dd::ZERO, random()), &|| (random(), random())],
        |(a, b): (Dd, Dd)| a.mul(b),
    );
}

#[test]
#[ignore = "timing measurement"]
fn whole_sampler_time_by_uniforms() {
    crate::ct::harden_thread();
    let draw = || -> Vec<(Dd, Dd)> { (0..PAIRS).map(|_| uniform_pair(&mut OsRng)).collect() };
    // Every pair the same easy value: each logarithm, cosine and sine takes its easy case.
    let easy: Vec<(Dd, Dd)> = vec![(Dd(0.5, 0.0), Dd(0.25, 0.0)); PAIRS];
    let pools = [vec![easy.clone(), easy], vec![draw(), draw()]];
    let run = |pools: &[Vec<Vec<(Dd, Dd)>>; 2], what: &str| {
        let mut times: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
        for _ in 0..20_000 {
            let class = OsRng.gen_range(0..2usize);
            let uniforms = &pools[class][OsRng.gen_range(0..2usize)];
            let start = Instant::now();
            std::hint::black_box(ball_from_uniforms(1000.0, std::hint::black_box(uniforms)));
            times[class].push(start.elapsed().as_nanos() as f64);
        }
        let (a, b, first, second) = orders(&times);
        println!(
            "{what}: {:.0} ns against {:.0} ns, t = {first:.2}, spread t = {second:.2}",
            a * BATCH as f64,
            b * BATCH as f64
        );
    };
    run(
        &[vec![draw(), draw()], vec![draw(), draw()]],
        "floor (random against random)",
    );
    run(&pools, "easy uniforms against random ones");
}
