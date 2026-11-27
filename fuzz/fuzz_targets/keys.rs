#![no_main]
//! Key files, share files and the protocol's wire encodings of `w` and `z`.
use libfuzzer_sys::fuzz_target;
use threshold_mldsa::mithril;

fuzz_target!(|data: &[u8]| {
    if let Some(key) = mithril::GroupKey::from_bytes(data) {
        // What parses must write back and parse again.
        assert!(mithril::GroupKey::from_bytes(&key.to_bytes()).is_some());
    }
    if let Some(share) = mithril::PartyKey::from_bytes(data) {
        assert!(mithril::PartyKey::from_bytes(&share.to_bytes()).is_some());
    }
    let _ = mithril::w_from_wire(data);
    let _ = mithril::z_from_wire(data);
    let _ = mithril::unpack_k(data);
});
