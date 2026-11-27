#![no_main]
//! Checkpoints, approvals, certificates, rosters and address books.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cairn_net::policy::Checkpoint::parse(data);
    let _ = cairn_policy::org::Approval::from_json(data);
    let _ = cairn_sidecar::Certificate::from_bytes(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = cairn_net::dkg::roster_from_json(text);
        let _ = cairn_net::cluster::parse_peers(text);
    }
});
