//! Leaf committee end to end: byte-exact FIPS 204 output, rejection hygiene, fault handling.

use rand::rngs::OsRng;
use std::sync::Arc;
use threshold_mldsa::{
    deal, fips204, sign, Behavior, Committee, FaultKind, Gadget, GroupPublic, Message, Round,
    ShapeError, SignError, SignPolicy, Signer, TrustedEngine,
};

fn committee(seed: u8, t: usize, n: usize) -> (Arc<GroupPublic>, Committee<Signer>) {
    let (group, shares) = deal(&[seed; 32], &[Gadget::new(t, n).unwrap()], &mut OsRng).unwrap();
    let group = Arc::new(group);
    let signers = shares
        .into_iter()
        .map(|s| Signer::new(s, group.clone()))
        .collect();
    let c = Committee::new(group.clone(), vec![], t, signers).unwrap();
    (group, c)
}

fn reference(seed: u8, msg: &[u8]) -> ([u8; fips204::SIGNATURE_BYTES], u32) {
    fips204::sign_reference(&fips204::keygen_internal(&[seed; 32]), msg)
}

#[test]
fn three_of_four_matches_single_signer_byte_for_byte() {
    for seed in 1..=6u8 {
        let msg = format!("checkpoint {seed}").into_bytes();
        let (group, mut c) = committee(seed, 3, 4);
        let out = sign(
            &mut c,
            &mut TrustedEngine::new(),
            &group,
            &msg,
            &SignPolicy::default(),
        )
        .unwrap();
        let (expect, rejections) = reference(seed, &msg);
        assert_eq!(
            out.signature, expect,
            "threshold output must equal the deterministic FIPS 204 signature"
        );
        assert_eq!(out.report.rejections, rejections);
        assert!(fips204::verify_standard(&group.pk, &msg, &out.signature));
        assert!(!fips204::verify_standard(
            &group.pk,
            b"other",
            &out.signature
        ));
    }
}

#[test]
fn four_of_six_signs_and_seven_is_refused() {
    let (group, mut c) = committee(11, 4, 6);
    let out = sign(
        &mut c,
        &mut TrustedEngine::new(),
        &group,
        b"m",
        &SignPolicy::default(),
    )
    .unwrap();
    assert_eq!(out.signature, reference(11, b"m").0);
    assert_eq!(Gadget::new(4, 7), Err(ShapeError::TooLarge(7)));
}

#[test]
fn rejected_attempts_open_nothing() {
    // Find a message whose signature needs at least two rejections.
    let (seed, msg) = (1u8..)
        .map(|s| (s, vec![s; 8]))
        .find(|(s, m)| reference(*s, m).1 >= 2)
        .unwrap();
    let (group, mut c) = committee(seed, 3, 4);
    let policy = SignPolicy {
        record_transcript: true,
        ..SignPolicy::default()
    };
    let out = sign(&mut c, &mut TrustedEngine::new(), &group, &msg, &policy).unwrap();
    assert!(out.report.rejections >= 2);
    let last = out.report.rejections;
    let mut opened = 0;
    for m in &out.report.wire.transcript {
        if let Message::HintCarry {
            header,
            accept,
            openings,
            hint,
        } = m
        {
            if header.attempt < last {
                assert!(
                    !accept && openings.is_empty() && hint.is_none(),
                    "rejected attempt leaked an opening"
                );
            } else if header.sender.len() == 1 {
                opened += openings.len();
            }
        }
        assert!(
            !matches!(m, Message::Abort { .. }),
            "a rejection is not a fault"
        );
    }
    assert_eq!(
        opened, 3,
        "exactly the accepted attempt's three shares are opened"
    );
    assert_eq!(out.report.fault_retries, 0);
}

#[test]
fn offline_signer_does_not_stall() {
    let (group, mut c) = committee(3, 3, 4);
    c.members_mut()[1].behavior = Behavior::Offline;
    let out = sign(
        &mut c,
        &mut TrustedEngine::new(),
        &group,
        b"m",
        &SignPolicy::default(),
    )
    .unwrap();
    assert_eq!(out.signature, reference(3, b"m").0);
    assert_eq!(
        out.report.fault_retries, 0,
        "silence at the commitment round costs no retry"
    );
    assert_eq!(out.report.wire.timeouts, 1, "and is waited for only once");
    assert_eq!(out.report.faults[0].culprit, Some(vec![2]));
}

#[test]
fn every_attributable_deviation_names_its_signer() {
    let cases = [
        (
            Behavior::SilentAt(Round::Challenge),
            FaultKind::Timeout(Round::Challenge),
        ),
        (
            Behavior::SilentAt(Round::MaskedResponse),
            FaultKind::Timeout(Round::MaskedResponse),
        ),
        (
            Behavior::SilentAt(Round::HintCarry),
            FaultKind::Timeout(Round::HintCarry),
        ),
        (Behavior::WrongChallenge, FaultKind::ChallengeMismatch),
        (Behavior::BadOpening, FaultKind::BadOpening),
        (Behavior::OpeningMismatch, FaultKind::OpeningMismatch),
        (Behavior::BadResponse, FaultKind::InconsistentResponse),
        (Behavior::BadSeedShare, FaultKind::BadSeedShare),
    ];
    for (behavior, kind) in cases {
        let (group, mut c) = committee(5, 3, 4);
        c.members_mut()[0].behavior = behavior;
        let out = sign(
            &mut c,
            &mut TrustedEngine::new(),
            &group,
            b"m",
            &SignPolicy::default(),
        )
        .unwrap();
        assert_eq!(out.signature, reference(5, b"m").0, "{behavior:?}");
        assert_eq!(out.report.fault_retries, 1, "{behavior:?}");
        assert_eq!(out.report.faults.len(), 1, "{behavior:?}");
        assert_eq!(out.report.faults[0].culprit, Some(vec![1]), "{behavior:?}");
        assert_eq!(out.report.faults[0].kind, kind, "{behavior:?}");
        assert!(c.excluded().contains(&1));
    }
}

#[test]
fn unattributed_mask_deviation_is_rotated_out() {
    let (group, mut c) = committee(7, 3, 4);
    c.members_mut()[2].behavior = Behavior::ShiftMask;
    let out = sign(
        &mut c,
        &mut TrustedEngine::new(),
        &group,
        b"m",
        &SignPolicy::default(),
    )
    .unwrap();
    assert_eq!(out.signature, reference(7, b"m").0);
    assert!(out.report.fault_retries >= 1 && out.report.fault_retries <= 4);
    assert!(out
        .report
        .faults
        .iter()
        .all(|f| f.kind == FaultKind::Unattributed && f.culprit.is_none()));
}

#[test]
fn losing_the_quorum_is_reported_not_hung() {
    let (group, mut c) = committee(8, 3, 4);
    c.members_mut()[0].behavior = Behavior::Offline;
    c.members_mut()[3].behavior = Behavior::Offline;
    let err = sign(
        &mut c,
        &mut TrustedEngine::new(),
        &group,
        b"m",
        &SignPolicy::default(),
    )
    .err()
    .unwrap();
    assert!(matches!(err, SignError::QuorumLost(f) if f.len() == 3));
}
