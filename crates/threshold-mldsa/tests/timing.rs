//! A timing measurement of the response round (round 3), the one step that mixes a party's
//! share into a value under a mask. Run by `scripts/timing-check.sh`; ignored otherwise,
//! because it needs a quiet machine and a release build.
//!
//! Method (as in dudect): time the same call for two classes of secret, interleaved at
//! random, drop the slowest tenth, and compare the means with Welch's t statistic. The
//! classes are the extremes: a share of all zeros and a share with every coefficient at the
//! bound, plus or minus eta. |t| below 4.5 is the usual "no leak detected" line. It is a
//! measurement on one processor, not a proof.

use rand::{rngs::OsRng, Rng};
use std::collections::BTreeMap;
use std::time::Instant;
use threshold_mldsa::fips204::{PolyVec, K, L, Q};
use threshold_mldsa::mithril::{keygen, PartyKey};

const ETA: i32 = 4;

fn share(index: u8, like: &PartyKey, coefficient: impl Fn(usize) -> i32) -> PartyKey {
    let vec = |len: usize| -> PolyVec {
        (0..len)
            .map(|_| std::array::from_fn(&coefficient))
            .collect()
    };
    PartyKey::from_shares(
        index,
        like.subsets()
            .into_iter()
            .map(|subset| (subset, (vec(L), vec(K))))
            .collect(),
    )
}

fn welch(a: &[f64], b: &[f64]) -> f64 {
    let stats = |v: &[f64]| {
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
        (mean, var, v.len() as f64)
    };
    let ((ma, va, na), (mb, vb, nb)) = (stats(a), stats(b));
    (ma - mb) / (va / na + vb / nb).sqrt()
}

#[test]
#[ignore = "timing measurement; run scripts/timing-check.sh"]
fn response_round_time_does_not_depend_on_the_share() {
    let samples: usize = std::env::var("CAIRN_TIMING_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4000);
    println!(
        "data-independent timing: {}",
        if threshold_mldsa::ct::harden_thread() {
            "on"
        } else {
            "not available on this processor"
        }
    );
    let (key, parties) = keygen(2, 3, &mut OsRng).expect("2-of-3");
    // CAIRN_TIMING_CONTROL=1 gives both classes the same share: whatever difference is then
    // measured comes from the machine and the method, not from the data.
    let control = std::env::var_os("CAIRN_TIMING_CONTROL").is_some();
    let bound = |j: usize| if j % 2 == 0 { ETA } else { Q - ETA };
    let classes = [
        share(0, &parties[0], |j| if control { bound(j) } else { 0 }),
        share(0, &parties[0], bound),
    ];
    // The other active party's openings are public and the same for every sample.
    let (other, other_commitment) = parties[1].round1(&key, &mut OsRng);
    let message = b"timing";
    let mut times: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
    let (mut accepted, mut runs) = ([0f64; 2], [0f64; 2]);
    for _ in 0..samples {
        let class = OsRng.gen_range(0..2usize);
        let (state, commitment) = classes[class].round1(&key, &mut OsRng);
        let revealed: BTreeMap<u8, Vec<PolyVec>> =
            [(0, state.reveal()), (1, other.reveal())].into();
        let commitments: BTreeMap<u8, [u8; 32]> = [(0, commitment), (1, other_commitment)].into();
        let start = Instant::now();
        let out = classes[class].round3(&key, state, message, &commitments, &revealed);
        let elapsed = start.elapsed().as_nanos() as f64;
        let out = std::hint::black_box(out).expect("round 3 ran");
        accepted[class] += out.iter().flatten().count() as f64 / out.len() as f64;
        runs[class] += 1.0;
        times[class].push(elapsed);
    }
    let mut pooled: Vec<f64> = times.iter().flatten().copied().collect();
    pooled.sort_by(f64::total_cmp);
    let cut = pooled[pooled.len() * 9 / 10];
    let kept: Vec<Vec<f64>> = times
        .iter()
        .map(|t| t.iter().copied().filter(|x| *x <= cut).collect())
        .collect();
    let t = welch(&kept[0], &kept[1]);
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64 / 1e3;
    println!(
        "response round: zero share {:.1} us (n={}), bound share {:.1} us (n={}), t = {t:.2}",
        mean(&kept[0]),
        kept[0].len(),
        mean(&kept[1]),
        kept[1].len()
    );
    println!(
        "accepted fraction: zero share {:.4}, bound share {:.4}",
        accepted[0] / runs[0],
        accepted[1] / runs[1]
    );
    assert!(t.abs() < 4.5, "timing differs between shares: t = {t:.2}");
}
