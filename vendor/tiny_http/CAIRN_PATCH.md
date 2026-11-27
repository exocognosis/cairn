# tiny_http 0.12.0, with one change

This is the published `tiny_http` 0.12.0 crate (sources, manifest and license files; its
benches, examples and tests are left out, and so are the dev-dependencies they used). The
workspace uses it through `[patch.crates-io]` in the root `Cargo.toml`.

The one change is in `src/util/equal_reader.rs`. When a request is dropped before its body is
read to the end, upstream drains the rest of the body into a buffer the size of everything the
`Content-Length` header still promises. A request that claims 99 GB and sends one byte made
the process try to allocate 99 GB, which aborts it on Linux. The buffer is now at most 64 KiB.

`src/lib.rs` also gained one `#![allow(...)]` line for two warnings current compilers raise.

Found by `crates/cairn-sidecar/tests/hostile_input.rs` on 2026-11-27. Drop this directory
when a release of `tiny_http` contains the fix.
