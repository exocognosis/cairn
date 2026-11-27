//! A statistical test of what the response round publishes. Run by `scripts/leak-check.sh`;
//! ignored otherwise, because it signs tens of thousands of times.
//!
//! A response is `z = c s + r`: the share `s` times a public challenge `c`, under a mask `r`.
//! Rejection is what makes the published `z` independent of `c s`. If it were skipped or
//! wrong, `z` would lean towards `c s`, and the inner product `<z, c s>` would average
//! `|c s|^2` instead of zero. The test measures that average over many responses, and prints
//! how large it would be with no rejection at all, which says how small a lean it could see.
//!
//! The share is the worst case: every coefficient at the bound. The control gives the party
//! an all-zero share and correlates its responses with the `c s` of the bound share, which
//! they cannot depend on.

use rand::rngs::OsRng;
use std::collections::BTreeMap;
use threshold_mldsa::fips204::{centered, challenge_mul, vec_add, vec_zero, PolyVec, L, Q};
use threshold_mldsa::mithril::{challenge_poly, keygen, recover_partition, PartyKey};

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
            .map(|subset| (subset, (vec(L), vec(threshold_mldsa::fips204::K))))
            .collect(),
    )
}

#[test]
#[ignore = "statistical measurement; run scripts/leak-check.sh"]
fn published_responses_do_not_lean_towards_the_share() {
    let samples: usize = std::env::var("CAIRN_LEAK_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let (key, parties) = keygen(2, 3, &mut OsRng).expect("2-of-3");
    let bound = share(0, &parties[0], |j| if j % 2 == 0 { ETA } else { Q - ETA });
    let zero = share(0, &parties[0], |_| 0);
    // The part of the bound share this party answers with when parties 0 and 1 sign.
    let mine = recover_partition(&key.params, &[0, 1])
        .and_then(|mut p| p.remove(&0))
        .expect("partition");
    let s1 = mine.iter().fold(vec_zero(L), |sum, subset| {
        vec_add(&sum, &bound.secret(subset).expect("subset").0)
    });
    let (other, other_commitment) = parties[1].round1(&key, &mut OsRng);
    let message = b"leak";

    // Per class: count, sum and sum of squares of <z, c s>; and the sum of |c s|^2.
    let mut stats = [(0f64, 0f64, 0f64, 0f64); 2];
    for sample in 0..samples {
        let class = sample % 2;
        let party = [&bound, &zero][class];
        let (state, commitment) = party.round1(&key, &mut OsRng);
        let revealed: BTreeMap<u8, Vec<PolyVec>> =
            [(0, state.reveal()), (1, other.reveal())].into();
        let commitments: BTreeMap<u8, [u8; 32]> = [(0, commitment), (1, other_commitment)].into();
        let out = party
            .round3(&key, state, message, &commitments, &revealed)
            .expect("round 3 ran");
        for (rep, z) in out.iter().enumerate() {
            let Some(z) = z else { continue };
            let cs = challenge_mul(&challenge_poly(&key, message, &revealed, rep), &s1);
            let (mut dot, mut norm) = (0f64, 0f64);
            for (a, b) in z.iter().flatten().zip(cs.iter().flatten()) {
                let (a, b) = (centered(*a) as f64, centered(*b) as f64);
                dot += a * b;
                norm += b * b;
            }
            let s = &mut stats[class];
            *s = (s.0 + 1.0, s.1 + dot, s.2 + dot * dot, s.3 + norm);
        }
    }
    let mut worst = 0f64;
    for (name, (n, sum, squares, norm)) in ["bound share", "zero share (control)"].iter().zip(stats)
    {
        let mean = sum / n;
        let deviation = ((squares / n - mean * mean) * n / (n - 1.0)).sqrt();
        let error = deviation / n.sqrt();
        let t = mean / error;
        let unrejected = norm / n;
        println!(
            "{name}: {n} responses, mean <z, cs> = {mean:.3e} +- {error:.3e} (t = {t:.2}); \
             with no rejection it would be {unrejected:.3e} (t = {:.0}), so a lean of {:.2}% \
             of that would show",
            unrejected / error,
            450.0 * error / unrejected
        );
        // The measurement must be able to see a response that skipped rejection.
        assert!(unrejected / error > 10.0, "too few samples to see a leak");
        worst = worst.max(t.abs());
    }
    assert!(
        worst < 4.5,
        "responses lean towards the share: |t| = {worst:.2}"
    );
}
