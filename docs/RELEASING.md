# Releasing, and checking a release

## What a release is

A tag `vX.Y.Z` on `main`. Pushing it runs `.github/workflows/release.yml`, which builds the
`cairn` binary for Linux x86-64, Linux arm64 and macOS arm64 and attaches each archive with a
SHA-256 checksum to the GitHub release.

Releases are not signed. The checksums come from the same place as the archives, so they
detect a damaged download, not a replaced one. To trust a binary without trusting the
download, rebuild it as described below.

## Before tagging

1. `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, `scripts/ct-check.sh`.
2. On an arm64 machine, `scripts/timing-check.sh`.
3. Set the version in `Cargo.toml` and `CITATION.cff`; run `cargo build` so `Cargo.lock`
   follows.
4. If `NET_VERSION` changed since the last tag, say so in docs/OPERATIONS.md under
   "Upgrading".
5. Commit, wait for CI on that commit, then tag it and push the tag.

## Rebuilding a release

The compiler is fixed by `rust-toolchain.toml` and every dependency by `Cargo.lock`; the one
dependency that is not from crates.io is in `vendor/`. `rustup` installs the right compiler
on first use.

```sh
git clone https://github.com/exocognosis/cairn && cd cairn
git checkout vX.Y.Z
scripts/release-build.sh
```

The script builds with source paths mapped out of the binary and prints its SHA-256.

What has been checked, on macOS arm64 on 2026-11-27:

- Two builds of one commit in the same build directory give the same binary.
- Two builds in different build directories differ in 48 bytes of 5.7 million and in nothing
  else. That is the size of the identifier the macOS linker stamps on a binary plus the hash
  that covers it; the cause was not traced further. So on macOS a checksum matches only if
  the checkout and build directory have the same absolute paths as the original build.

What has not been checked: Linux, and whether a build on your machine equals the published
archive's binary. The release workflow runs the same script, so with the same paths,
operating system and architecture it should. If your build differs, count the differing
bytes (`cmp -l a b | wc -l`) before concluding anything: a few dozen is the linker, more is
not.

## Dependencies

`Cargo.lock` is committed and builds use `--locked`. There is no automated advisory check in
CI yet (`cargo audit` or `cargo deny`); run one by hand before a release if you have it.
