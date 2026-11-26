//! Both engines behind the one interface: a caller that only knows `ThresholdSigner` gets a
//! signature any FIPS 204 verifier accepts, whichever backend was configured.

use cairn_core::{verify, Backend, LocalFlat, LocalTower, Roster, SignerError, ThresholdSigner};
use cascade_tower::{Tower, TowerParams};
use rand::rngs::OsRng;
use threshold_mldsa::{SignPolicy, TrustedEngine};

fn build(backend: Backend) -> Box<dyn ThresholdSigner> {
    match backend {
        Backend::Flat => Box::new(
            LocalFlat::deal(&Roster::uniform(2, (1..=3).map(|i| format!("p{i}")))).unwrap(),
        ),
        Backend::Tower => Box::new(LocalTower {
            tower: Tower::deal(&[7; 32], &TowerParams::default_16(), &mut OsRng).unwrap(),
            engine: TrustedEngine::new(),
            policy: SignPolicy::default(),
        }),
    }
}

#[test]
fn either_backend_signs_opaque_bytes_through_the_same_interface() {
    for name in ["flat", "tower"] {
        let backend: Backend = name.parse().unwrap();
        let mut signer = build(backend);
        assert_eq!(signer.backend(), backend);
        let message = b"not a checkpoint: any bytes";
        let signature = signer.sign(message).unwrap();
        assert!(verify(&signer.public_key(), message, &signature));
        assert!(!verify(
            &signer.public_key(),
            b"another message",
            &signature
        ));
        assert!(matches!(
            signer.reshare(&Roster::uniform(2, ["a".to_owned(), "b".to_owned()])),
            Err(SignerError::Unsupported(_))
        ));
    }
    assert!("frost".parse::<Backend>().is_err());
}

#[test]
fn backends_are_as_deterministic_as_they_say() {
    for backend in [Backend::Flat, Backend::Tower] {
        let mut signer = build(backend);
        let (a, b) = (signer.sign(b"m").unwrap(), signer.sign(b"m").unwrap());
        assert_eq!(a == b, backend.deterministic(), "{}", backend.name());
    }
}
