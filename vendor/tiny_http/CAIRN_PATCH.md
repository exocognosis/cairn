# tiny_http 0.12.0, with three changes

This is the published `tiny_http` 0.12.0 crate (sources, manifest and license files; its
benches, examples and tests are left out, and so are the dev-dependencies they used). The
workspace uses it through `[patch.crates-io]` in the root `Cargo.toml`.

The first change is in `src/util/equal_reader.rs`. When a request is dropped before its body is
read to the end, upstream drains the rest of the body into a buffer the size of everything the
`Content-Length` header still promises. A request that claims 99 GB and sends one byte made
the process try to allocate 99 GB, which aborts it on Linux. The buffer is now at most 64 KiB.

The second change is in `src/connection.rs` and the accept loop in `src/lib.rs`: every
accepted socket gets a 10 second read and write timeout. Upstream sets none, so a client that
connects and sends nothing, or sends headers and no body, held a thread for as long as it
liked. An idle keep-alive connection is now closed after 10 seconds; clients reconnect. Found
by the automated review of 2026-11-27 (DECISIONS.md D-141).

The third change is in the accept loop in `src/lib.rs`: the server holds at most 256 open
connections, and at most 32 from one address that is not this machine. Upstream starts a
thread for every connection it is offered. A connection over the limit is closed at once.
Local addresses are not counted one by one because a TLS front on the same machine brings
every caller in from loopback; the front has its own limits (`cairn-gateway/src/tls.rs`).

`src/lib.rs` also gained one `#![allow(...)]` line for two warnings current compilers raise.

Found by `crates/cairn-sidecar/tests/hostile_input.rs` on 2026-11-27. Drop this directory
when a release of `tiny_http` contains the fix.
