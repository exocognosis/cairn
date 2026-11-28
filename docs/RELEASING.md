# Releasing, and checking a release

## What a release is

A tag `vX.Y.Z` on `main`. Pushing it runs `.github/workflows/release.yml`, which builds the
`cairn` binary for Linux x86-64, Linux arm64 and macOS arm64 and attaches each archive with a
SHA-256 checksum to the GitHub release.

From 0.7.2 on, each archive also has a build provenance statement: GitHub
signs, with the identity of the workflow run and no key that anyone holds, that this archive
was built by this repository's release workflow from this commit. Check one with

```sh
gh attestation verify cairn-vX.Y.Z-<target>.tar.gz --repo exocognosis/cairn
```

That shows the archive came from the workflow and was not replaced afterwards. It does not
show the source is sound, and it trusts GitHub. To avoid trusting the download at all,
rebuild it as described below. It first ran for 0.7.2: each of the three archives has a statement recorded against its
digest. The verify command above has not been run against a downloaded 0.7.2 archive.

## Before tagging

1. `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, `scripts/ct-check.sh`.
2. On a quiet arm64 machine, `scripts/timing-check.sh`. (An x86-64 machine with dedicated
   cores is worth the few cents when the sampler or the arithmetic changed: the one
   data-dependent branch found so far showed only there, D-145.) Its response-round test compares an
   all-zero share with one at the bound and is known to fail about one run in four for the
   reason in docs/SAMPLER.md ("a smaller difference remains"). A failure there with t
   above about 8, or any failure of the mask-round test, is new and blocks the tag.
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

`Cargo.lock` is committed and builds use `--locked`. CI runs `cargo audit` on every push and
every Monday, and fails on a known vulnerability. On 2026-11-27 it reported none, and two
"unmaintained" notices: `bincode` 1.3 (key files and network frames) and `rustls-pemfile` 2
(reading certificates). Neither has a known vulnerability; replacing `bincode` changes file
and wire formats and is not done.
