//! How far is the mask sampler from the formula it implements?
//!
//! The same uniforms go through [`ball_from_uniforms`] (double-double arithmetic, about 106
//! bits) and through a 256-bit evaluation of the same formula (Box-Muller, normalise,
//! scale). The masks a party uses are the rounded coordinates, so the test checks that every
//! one is the correct rounding and records the largest error before rounding.
//! `CAIRN_SAMPLER_SAMPLES=<n>` runs more samples (each is 2816 coordinates; the default
//! keeps the suite fast).
//!
//! What this measures: the arithmetic, including cairn's own `ln` and `cos`. What it does
//! not: that the uniforms carry 106 random bits rather than being real numbers. See
//! docs/SAMPLER.md.

use super::*;
use astro_float::{BigFloat, Consts, RoundingMode};

const P: usize = 256;
const RM: RoundingMode = RoundingMode::ToEven;

fn big(x: f64) -> BigFloat {
    BigFloat::from_f64(x, P)
}

fn wide(x: Dd) -> BigFloat {
    big(x.0).add(&big(x.1), P, RM)
}

fn as_f64(x: &BigFloat) -> f64 {
    x.to_string().parse().unwrap_or(f64::NAN)
}

fn below(x: &BigFloat, bound: f64) -> bool {
    x.cmp(&big(bound)).is_some_and(|c| c < 0)
}

/// The sampler's formula in 256-bit arithmetic.
fn reference(radius: f64, uniforms: &[(Dd, Dd)], cc: &mut Consts) -> Vec<BigFloat> {
    let two_pi = cc.pi(P, RM).mul(&big(2.0), P, RM);
    let g: Vec<BigFloat> = uniforms
        .iter()
        .flat_map(|&(u1, u2)| {
            let radial = wide(u1).ln(P, RM, cc).mul(&big(-2.0), P, RM).sqrt(P, RM);
            let angle = two_pi.mul(&wide(u2), P, RM);
            [
                radial.mul(&angle.cos(P, RM, cc), P, RM),
                radial.mul(&angle.sin(P, RM, cc), P, RM),
            ]
        })
        .collect();
    let norm = g
        .iter()
        .fold(big(0.0), |sum, x| sum.add(&x.mul(x, P, RM), P, RM))
        .sqrt(P, RM);
    let scale = big(radius).div(&norm, P, RM);
    g[..DIM].iter().map(|x| x.mul(&scale, P, RM)).collect()
}

#[test]
fn sampler_matches_a_256_bit_evaluation() {
    let samples: usize = std::env::var("CAIRN_SAMPLER_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let mut cc = Consts::new().expect("constants");
    let mut rng = rand::thread_rng();
    let half = big(0.5);
    let (mut coordinates, mut differing) = (0u64, 0u64);
    let mut worst = big(0.0);
    // The largest randomness radius of any committee size: the largest absolute error.
    let radius = (2..=6)
        .flat_map(|n| (2..=n).filter_map(move |t| params_65(t, n)))
        .map(|p| p.r_prime)
        .fold(0.0, f64::max);
    for _ in 0..samples {
        let uniforms: Vec<(Dd, Dd)> = (0..PAIRS).map(|_| uniform_pair(&mut rng)).collect();
        for (u1, u2) in &uniforms {
            assert!(u1.0 > 0.0 && u1.0 <= 1.0 && (0.0..=1.0).contains(&u2.0));
            assert!(
                below(&wide(*u1), 1.0),
                "the first uniform must stay below 1"
            );
        }
        let fast = ball_from_uniforms(radius, &uniforms);
        let exact = reference(radius, &uniforms, &mut cc);
        for (i, (x, big_x)) in fast.iter().zip(&exact).enumerate() {
            // The first L*N coordinates are scaled by nu before rounding (round1).
            let nu = if i < L * N { NU } else { 1.0 };
            let (x, big_x) = (x.mul_f64(nu), big_x.mul(&big(nu), P, RM));
            let error = big_x.sub(&wide(x), P, RM).abs();
            if error.cmp(&worst).is_some_and(|c| c > 0) {
                worst = error;
            }
            // Is the integer the party uses the correct rounding of the exact value?
            let off = big_x.sub(&big(x.round() as f64), P, RM).abs();
            coordinates += 1;
            if off.cmp(&half).is_some_and(|c| c > 0) {
                differing += 1;
            }
        }
    }
    println!(
        "sampler precision: {samples} samples, {coordinates} coordinates, radius {radius:.0}: \
         {differing} rounded differently, largest error before rounding {:.3e}",
        as_f64(&worst)
    );
    assert!(
        below(&worst, 1e-20),
        "sampler is further than 1e-20 from the formula"
    );
    assert_eq!(differing, 0);
}

/// `ln`, `cos_sin_turn`, `sqrt`, `div` and `round` against 256-bit values over their input
/// ranges, including the ends where a series or a reduction would first go wrong.
#[test]
fn double_double_functions_are_accurate() {
    let mut cc = Consts::new().expect("constants");
    let mut rng = rand::thread_rng();
    let two_pi = cc.pi(P, RM).mul(&big(2.0), P, RM);
    let tiny = 0.5f64.powi(107);
    let mut inputs: Vec<Dd> = [
        tiny,
        1e-17,
        0.25,
        0.5,
        std::f64::consts::FRAC_1_SQRT_2,
        0.75,
        0.125,
        0.375,
        0.625,
        0.875,
    ]
    .iter()
    .flat_map(|&x| {
        [
            Dd(x, 0.0),
            Dd::from_sum(x, x * 1e-17),
            Dd::from_sum(x, tiny),
        ]
    })
    .collect();
    inputs.push(Dd::from_sum(1.0, -tiny));
    inputs.push(Dd::from_sum(0.5, -tiny));
    inputs.extend((0..3000).flat_map(|_| {
        let (a, b) = uniform_pair(&mut rng);
        [a, b]
    }));
    // Small arguments: products of uniforms.
    inputs.extend((0..500).map(|_| {
        let (a, b) = uniform_pair(&mut rng);
        (0..rng.gen_range(1..12)).fold(a, |x, _| x.mul(b))
    }));
    let mut worst = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    for &u in &inputs {
        let exact_u = wide(u);
        if u.0 > 0.0 && below(&exact_u, 1.0) {
            // Relative error of ln, with a floor next to 1 where ln itself vanishes.
            let exact = exact_u.ln(P, RM, &mut cc);
            let error = exact.sub(&wide(u.ln()), P, RM).abs();
            let scale = exact.abs().add(&big(1e-3), P, RM);
            worst.0 = worst.0.max(as_f64(&error.div(&scale, P, RM)));
            // sqrt and div, relative.
            let error = exact_u.sqrt(P, RM).sub(&wide(u.sqrt()), P, RM).abs();
            worst.2 = worst.2.max(as_f64(&error.div(&exact_u.sqrt(P, RM), P, RM)));
            let quotient = big(571_412.0).div(&exact_u, P, RM);
            let error = quotient.sub(&wide(Dd(571_412.0, 0.0).div(u)), P, RM).abs();
            worst.3 = worst.3.max(as_f64(&error.div(&quotient, P, RM)));
        }
        if u.0 < 1.0 {
            let angle = two_pi.mul(&exact_u, P, RM);
            let (cos, sin) = u.cos_sin_turn();
            let cos_error = angle.cos(P, RM, &mut cc).sub(&wide(cos), P, RM).abs();
            let sin_error = angle.sin(P, RM, &mut cc).sub(&wide(sin), P, RM).abs();
            worst.1 = worst.1.max(as_f64(&cos_error)).max(as_f64(&sin_error));
        }
    }
    println!(
        "double-double: ln {:.2e} (relative), cos and sin {:.2e} (absolute), sqrt {:.2e}, div {:.2e} \
         (relative), over {} inputs",
        worst.0,
        worst.1,
        worst.2,
        worst.3,
        inputs.len()
    );
    assert!(worst.0 < 1e-29 && worst.1 < 1e-29 && worst.2 < 1e-29 && worst.3 < 1e-29);
    // Rounding: integers, near-halves on both sides, negatives.
    for (value, expected) in [
        (Dd(3.0, 0.0), 3),
        (Dd::from_sum(2.5, 1e-20), 3),
        (Dd::from_sum(2.5, -1e-20), 2),
        (Dd::from_sum(-2.5, -1e-20), -3),
        (Dd::from_sum(-2.5, 1e-20), -2),
        (Dd::from_sum(3_428_471.499_99, 0.0), 3_428_471),
        (Dd::from_sum(-3_428_471.500_01, 0.0), -3_428_472),
        (Dd::from_sum(0.4999999, 0.0), 0),
    ] {
        assert_eq!(value.round(), expected, "{value:?}");
    }
}

#[test]
#[ignore = "timing printout"]
fn sampler_speed() {
    let mut rng = rand::thread_rng();
    let uniforms: Vec<(Dd, Dd)> = (0..PAIRS).map(|_| uniform_pair(&mut rng)).collect();
    let start = std::time::Instant::now();
    let mut sink = 0.0;
    for _ in 0..50 {
        sink += ball_from_uniforms(500_000.0, &uniforms)[7].0;
    }
    let ball = start.elapsed() / 50;
    let start = std::time::Instant::now();
    for (u1, _) in &uniforms {
        sink += u1.ln().0;
    }
    let ln = start.elapsed();
    let start = std::time::Instant::now();
    for (_, u2) in &uniforms {
        sink += u2.cos_sin_turn().0 .0;
    }
    println!(
        "one ball: {ball:?}; of which ln {ln:?}, cos {:?} ({sink})",
        start.elapsed()
    );
}
