#![no_main]
//! A network frame as the transport reads it from a peer: a length, then that many bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let mut stream = data;
    let _ = runtime.block_on(cairn_net::transport::read_frame(&mut stream));
});
