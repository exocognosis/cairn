//! 16-signer tower (3-of-4 leaves under a 3-of-4 root) end to end.

use cascade_tower::{Tower, TowerParams};
use rand::rngs::OsRng;
use threshold_mldsa::{
    fips204, Behavior, FaultKind, Message, Round, SignError, SignPolicy, TrustedEngine,
};

fn tower(seed: u8) -> Tower {
    Tower::deal(&[seed; 32], &TowerParams::default_16(), &mut OsRng).unwrap()
}

fn reference(seed: u8, msg: &[u8]) -> [u8; fips204::SIGNATURE_BYTES] {
    fips204::sign_reference(&fips204::keygen_internal(&[seed; 32]), msg).0
}

#[test]
fn sixteen_signers_produce_the_single_signer_signature() {
    for seed in 20..24u8 {
        let msg = [b"tower ".as_slice(), &[seed]].concat();
        let mut t = tower(seed);
        let policy = SignPolicy { record_transcript: true, ..SignPolicy::default() };
        let out = t.sign(&mut TrustedEngine::new(), &msg, &policy).unwrap();
        assert_eq!(out.signature.len(), 3309);
        assert_eq!(out.signature, reference(seed, &msg));
        assert!(fips204::verify_standard(t.public_key(), &msg, &out.signature));
        // Nine signers (three per active leaf) carried the attempt; nobody opened a rejected one.
        let last = out.report.rejections;
        let mut openers = 0;
        for m in &out.report.wire.transcript {
            if let Message::HintCarry { header, accept, openings, .. } = m {
                assert_eq!(*accept, header.attempt == last);
                assert!(*accept || openings.is_empty());
                openers += (*accept && header.sender.len() == 2) as usize;
            }
        }
        assert_eq!(openers, 9);
    }
}

#[test]
fn three_offline_signers_never_block() {
    // Below the blocking bound of 4, whatever the placement.
    for offline in [[[1, 1], [1, 2], [2, 1]], [[1, 1], [2, 2], [3, 3]], [[4, 1], [4, 2], [4, 3]], [[2, 4], [3, 1], [3, 2]]] {
        let mut t = tower(30);
        for p in offline {
            t.signer_mut(&p).unwrap().behavior = Behavior::Offline;
        }
        let out = t.sign(&mut TrustedEngine::new(), b"m", &SignPolicy::default()).unwrap();
        assert_eq!(out.signature, reference(30, b"m"), "{offline:?}");
        assert_eq!(out.report.fault_retries, 0, "{offline:?}");
    }
}

#[test]
fn four_offline_signers_in_two_leaves_block_and_it_is_reported() {
    let mut t = tower(31);
    for p in [[1, 1], [1, 2], [2, 1], [2, 2]] {
        t.signer_mut(&p).unwrap().behavior = Behavior::Offline;
    }
    let err = t.sign(&mut TrustedEngine::new(), b"m", &SignPolicy::default()).err().unwrap();
    assert!(matches!(err, SignError::QuorumLost(_)));
    // Back online at the next epoch.
    for p in [[1, 1], [1, 2], [2, 1], [2, 2]] {
        t.signer_mut(&p).unwrap().behavior = Behavior::Honest;
    }
    t.reinstate();
    assert!(t.sign(&mut TrustedEngine::new(), b"m", &SignPolicy::default()).is_ok());
}

#[test]
fn malicious_signer_is_named_by_full_path_and_replaced() {
    let cases = [
        (Behavior::SilentAt(Round::MaskedResponse), FaultKind::Timeout(Round::MaskedResponse)),
        (Behavior::WrongChallenge, FaultKind::ChallengeMismatch),
        (Behavior::BadOpening, FaultKind::BadOpening),
        (Behavior::OpeningMismatch, FaultKind::OpeningMismatch),
        (Behavior::BadResponse, FaultKind::InconsistentResponse),
        (Behavior::BadSeedShare, FaultKind::BadSeedShare),
    ];
    for (behavior, kind) in cases {
        let mut t = tower(32);
        t.signer_mut(&[3, 2]).unwrap().behavior = behavior;
        let out = t.sign(&mut TrustedEngine::new(), b"m", &SignPolicy::default()).unwrap();
        assert_eq!(out.signature, reference(32, b"m"), "{behavior:?}");
        assert_eq!(out.report.faults.len(), 1, "{behavior:?}");
        assert_eq!(out.report.faults[0].culprit, Some(vec![3, 2]), "{behavior:?}");
        assert_eq!(out.report.faults[0].kind, kind, "{behavior:?}");
        assert_eq!(out.report.fault_retries, 1);
    }
}

#[test]
fn one_malicious_signer_per_leaf_still_cannot_stall() {
    let mut t = tower(33);
    t.signer_mut(&[1, 1]).unwrap().behavior = Behavior::BadResponse;
    t.signer_mut(&[2, 2]).unwrap().behavior = Behavior::SilentAt(Round::HintCarry);
    t.signer_mut(&[3, 3]).unwrap().behavior = Behavior::WrongChallenge;
    t.signer_mut(&[4, 1]).unwrap().behavior = Behavior::Offline;
    let out = t.sign(&mut TrustedEngine::new(), b"m", &SignPolicy::default()).unwrap();
    assert_eq!(out.signature, reference(33, b"m"));
    assert!(out.report.fault_retries <= 3);
}

#[test]
fn unattributed_deviation_inside_a_leaf_is_rotated_out_at_the_root() {
    let mut t = tower(34);
    t.signer_mut(&[3, 1]).unwrap().behavior = Behavior::ShiftMask;
    let out = t.sign(&mut TrustedEngine::new(), b"m", &SignPolicy::default()).unwrap();
    assert_eq!(out.signature, reference(34, b"m"));
    assert!((1..=4).contains(&out.report.fault_retries));
}

#[test]
fn committee_ceiling_holds_at_every_tier() {
    assert!(TowerParams::new(&[(3, 4), (5, 7)]).is_err());
    assert!(TowerParams::new(&[(7, 8), (3, 4)]).is_err());
    let six = TowerParams::new(&[(4, 6), (4, 6)]).unwrap();
    assert_eq!((six.signers(), six.min_forging_coalition(), six.min_blocking_coalition()), (36, 16, 9));
    let mut t = Tower::deal(&[35; 32], &six, &mut OsRng).unwrap();
    let out = t.sign(&mut TrustedEngine::new(), b"m", &SignPolicy::default()).unwrap();
    assert_eq!(out.signature, reference(35, b"m"));
}
