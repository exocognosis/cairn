//! Mixed committees: some parties are this crate, the rest are the paper authors' reference
//! implementation, driven one protocol step at a time through `go test`.
//!
//! Run with `scripts/reference-interop.sh`. The reference generates the key; this side
//! imports the shares, rebuilds the public key, and both sides sign together. Both combine
//! procedures run on the same transcript and must return the same bytes.

use super::*;
use rand::{rngs::OsRng, RngCore};
use std::path::PathBuf;
use std::process::Command;

struct Reference {
    pkg: PathBuf,
    dir: PathBuf,
    t: usize,
    n: usize,
    seed: String,
}

impl Reference {
    fn run(&self, mode: &str, extra: &[(&str, String)]) {
        let out = Command::new("go")
            .args(["test", "-count=1", "-run", "^TestCairnInterop$", "."])
            .current_dir(&self.pkg)
            .env("CAIRN_MODE", mode)
            .env("CAIRN_DIR", &self.dir)
            .env("CAIRN_T", self.t.to_string())
            .env("CAIRN_N", self.n.to_string())
            .env("CAIRN_SEED", &self.seed)
            .envs(extra.iter().map(|(k, v)| (*k, v.as_str())))
            .output()
            .expect("go must be installed");
        assert!(
            out.status.success(),
            "reference {mode} failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(name)).unwrap()
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.join(name), bytes).unwrap()
    }
}

const POLY_BYTES: usize = 4 * N;

fn polys(bytes: &[u8], count: usize) -> PolyVec {
    (0..count)
        .map(|i| {
            std::array::from_fn(|j| {
                let at = i * POLY_BYTES + 4 * j;
                red(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as i64)
            })
        })
        .collect()
}

fn raw(v: &[Poly]) -> Vec<u8> {
    v.iter()
        .flatten()
        .flat_map(|c| (red(*c as i64) as u32).to_le_bytes())
        .collect()
}

fn list(ids: &[u8]) -> String {
    ids.iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn random_hex(len: usize) -> String {
    let mut b = vec![0u8; len];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One configuration: sign until both sides produce a signature. Returns (attempts,
/// answers by reference parties, answers by our parties, repetitions offered to each side).
fn mixed_committee(t: usize, n: usize, active: &[u8], ours: &[u8]) -> (usize, usize, usize, usize) {
    let pkg = PathBuf::from(std::env::var("CAIRN_REFERENCE_PKG").expect("CAIRN_REFERENCE_PKG"));
    let dir = std::env::temp_dir().join(format!("cairn-interop-{}", random_hex(8)));
    std::fs::create_dir_all(&dir).unwrap();
    let go = Reference {
        pkg,
        dir,
        t,
        n,
        seed: random_hex(32),
    };
    let theirs: Vec<u8> = active
        .iter()
        .copied()
        .filter(|i| !ours.contains(i))
        .collect();

    // The reference deals the key; we import every subset secret it produced.
    go.run("keygen", &[]);
    let keys = go.read("keys.bin");
    let rho: [u8; 32] = keys[..32].try_into().unwrap();
    let their_pk = &keys[32..32 + PUBLIC_KEY_BYTES];
    let mut at = 32 + PUBLIC_KEY_BYTES;
    let count = keys[at] as usize;
    at += 1;
    let mut shares: BTreeMap<Subset, (PolyVec, PolyVec)> = BTreeMap::new();
    for _ in 0..count {
        let mask = keys[at];
        let subset: Subset = (0..n as u8).filter(|i| mask >> i & 1 == 1).collect();
        let s1 = polys(&keys[at + 1..], L);
        let s2 = polys(&keys[at + 1 + L * POLY_BYTES..], K);
        at += 1 + (L + K) * POLY_BYTES;
        shares.insert(subset, (s1, s2));
    }
    assert_eq!(at, keys.len());
    assert_eq!(
        shares.keys().cloned().collect::<Vec<_>>(),
        all_subsets(t, n)
    );
    let subset_keys: BTreeMap<Subset, PolyVec> = shares
        .iter()
        .map(|(s, secret)| (s.clone(), subset_public(&rho, secret)))
        .collect();
    let t_full = subset_keys
        .values()
        .fold(vec_zero(K), |acc, ts| vec_add(&acc, ts));
    let key = GroupKey::from_parts(t, n, rho, &t_full, subset_keys).unwrap();
    assert_eq!(&key.pk[..], their_pk, "public keys differ");
    let parties: Vec<PartyKey> = ours
        .iter()
        .map(|i| {
            let mine = shares
                .iter()
                .filter(|(s, _)| s.contains(i))
                .map(|(s, v)| (s.clone(), v.clone()))
                .collect();
            PartyKey::from_shares(*i, mine)
        })
        .collect();

    let reps = key.params.reps;
    let act_mask: u32 = active.iter().map(|i| 1u32 << i).sum();
    let (mut answers_theirs, mut answers_ours, mut offered) = (0, 0, 0);
    for attempt in 1..=40 {
        let mut message = [0u8; 32];
        OsRng.fill_bytes(&mut message);
        // The reference hashes tr || msg; FIPS 204 hashes tr || 0 || len(ctx) || msg.
        let their_message: String = [0u8, 0]
            .iter()
            .chain(&message)
            .map(|x| format!("{x:02x}"))
            .collect();
        let env = [
            ("CAIRN_RHOP", random_hex(64)),
            ("CAIRN_MSG", their_message),
            ("CAIRN_ACT", act_mask.to_string()),
        ];
        let with_ids = |ids: &[u8]| {
            let mut e = env.to_vec();
            e.push(("CAIRN_IDS", list(ids)));
            e
        };

        // Round 1 and 2: commitments and openings from both sides.
        let mut revealed: BTreeMap<u8, Vec<PolyVec>> = BTreeMap::new();
        let mut commitments: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
        let mut states = Vec::new();
        for party in &parties {
            let (state, cmt) = party.round1(&key, &mut OsRng);
            revealed.insert(party.index, state.reveal());
            commitments.insert(party.index, cmt);
            states.push(state);
        }
        go.run("commit", &with_ids(&theirs));
        for id in &theirs {
            let bytes = go.read(&format!("w_{id}.bin"));
            let ws: Vec<PolyVec> = (0..reps)
                .map(|rep| polys(&bytes[rep * K * POLY_BYTES..], K))
                .collect();
            commitments.insert(*id, commitment(&key.pk, *id, &ws));
            revealed.insert(*id, ws);
        }
        let wfinal: Vec<u8> = (0..reps)
            .flat_map(|rep| raw(&aggregate_w(&revealed, rep)))
            .collect();
        go.write("wfinal.bin", &wfinal);

        // Round 3: responses from both sides.
        let mut responses: BTreeMap<u8, Vec<Option<PolyVec>>> = BTreeMap::new();
        go.run("respond", &with_ids(&theirs));
        for id in &theirs {
            let bytes = go.read(&format!("z_{id}.bin"));
            // The reference leaves a rejected repetition as the zero vector.
            let zs: Vec<Option<PolyVec>> = (0..reps)
                .map(|rep| {
                    let chunk = &bytes[rep * L * POLY_BYTES..(rep + 1) * L * POLY_BYTES];
                    chunk.iter().any(|b| *b != 0).then(|| polys(chunk, L))
                })
                .collect();
            answers_theirs += zs.iter().flatten().count();
            responses.insert(*id, zs);
        }
        for (party, state) in parties.iter().zip(states) {
            let zs = party
                .round3(&key, state, &message, &commitments, &revealed)
                .expect("our party refused the transcript");
            answers_ours += zs.iter().flatten().count();
            let bytes: Vec<u8> = zs
                .iter()
                .flat_map(|z| raw(z.as_deref().unwrap_or(&vec_zero(L))))
                .collect();
            go.write(&format!("z_{}.bin", party.index), &bytes);
            responses.insert(party.index, zs);
        }
        offered += reps;

        // Our public check of each response must clear the reference's parties too.
        assert_eq!(blame(&key, &message, &revealed, &responses), Some(vec![]));

        // Both combine procedures on the same transcript.
        let our_sig = combine(&key, &message, &revealed, &responses).map(|s| s.to_vec());
        go.run("combine", &with_ids(active));
        let their_sig = Some(go.read("sig.bin")).filter(|s| !s.is_empty());
        assert_eq!(our_sig, their_sig, "combine results differ");
        if let Some(sig) = our_sig {
            let sig: [u8; SIGNATURE_BYTES] = sig.try_into().unwrap();
            assert!(fips204::verify_standard(&key.pk, &message, &sig));
            let _ = std::fs::remove_dir_all(&go.dir);
            return (attempt, answers_theirs, answers_ours, offered);
        }
    }
    panic!("no signature in 40 attempts");
}

#[test]
#[ignore = "needs go and the reference checkout; run scripts/reference-interop.sh"]
fn reference_interop() {
    let configs: &[(usize, usize, &[u8], &[u8])] = &[
        (2, 3, &[0, 2], &[0]),
        (2, 3, &[1, 2], &[2]),
        (3, 4, &[0, 1, 3], &[1]),
        (3, 4, &[1, 2, 3], &[1, 3]),
        (3, 5, &[0, 2, 4], &[2]),
        (4, 5, &[0, 1, 3, 4], &[0, 3]),
    ];
    // CAIRN_INTEROP_ROUNDS repeats every committee with a new key and new randomness, and
    // adds up how often each implementation's parties answer: the same rejection test on
    // the same kind of share must answer at the same rate.
    let rounds: usize = std::env::var("CAIRN_INTEROP_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    for (t, n, active, ours) in configs {
        let (mut attempts, mut theirs, mut mine, mut offered) = (0, 0, 0, 0);
        for _ in 0..rounds {
            let (a, b, c, d) = mixed_committee(*t, *n, active, ours);
            attempts += a;
            theirs += b;
            mine += c;
            offered += d;
        }
        let n_ours = ours.len();
        let n_theirs = active.len() - n_ours;
        let (p_theirs, p_mine) = (
            theirs as f64 / (offered * n_theirs) as f64,
            mine as f64 / (offered * n_ours) as f64,
        );
        // Two-proportion z statistic for the difference in answer rates.
        let (n1, n2) = ((offered * n_theirs) as f64, (offered * n_ours) as f64);
        let pooled = (theirs + mine) as f64 / (n1 + n2);
        let z = (p_theirs - p_mine) / (pooled * (1.0 - pooled) * (1.0 / n1 + 1.0 / n2)).sqrt();
        println!(
            "{t}-of-{n} active {active:?} cairn {ours:?}: {rounds} key(s), {attempts} attempt(s), \
             every one checked; answer rate reference {p_theirs:.3} (n={n1}), cairn {p_mine:.3} \
             (n={n2}), z = {z:.2}",
        );
    }
}
