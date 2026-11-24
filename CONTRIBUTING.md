# Contributing

cairn is research code. Corrections, measurements and reviews are as useful as features.

The code is MIT licensed, and contributions are accepted under the same license.

## Getting set up

```bash
cargo test --workspace
```

This needs only Rust 1.80 or newer. Tests that need external programs print `SKIPPED` when
those are missing. To run everything:

```bash
./scripts/setup-verifiers.sh
```

```bash
CAIRN_REQUIRE_EXTERNAL_VERIFIERS=1 cargo test --workspace
```

`setup-verifiers.sh` expects a pqc-sidecar checkout next to this repository and Node 20+.

## Before you open a pull request

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

CI runs the same three checks.

## Rules that are not negotiable

- **Output stays FIPS 204.** `ExpandMask` is the exact standard function, encodings are
  standard, and no verifier is modified. A change that breaks the byte-for-byte comparison
  with the reference signer is a bug.
- **No committee larger than six**, and the root MPC stays at three parties.
- **A rejected attempt reveals one bit.** Do not add logging, messages or errors that expose
  which bound failed or any value of a rejected attempt.
- **Say what is and is not secure.** Documentation must not claim more than the tests and runs
  show. If you measured something, say how; if you did not, say so.

## Where things are

| Change | Look in |
|---|---|
| FIPS 204 arithmetic, shares, compression | `crates/threshold-mldsa` |
| Tower shape, bounds, epoch assignment | `crates/cascade-tower` |
| MPC wire protocol, stand-in backend | `crates/mpc-bridge` |
| Networking, nodes, coordinator, TLS | `crates/cairn-net` |
| CLI, certificates, KMS endpoint, benchmarks | `crates/cairn-sidecar` |
| The MPC circuit | `mpc/mp-spdz` |

Record any non-obvious design choice as a new entry in `DECISIONS.md`, with the reason and the
cost. Protocol changes also belong in `ARCHITECTURE.md`.

## Good first contributions

- Run the two-host or three-host layout and report numbers (ROADMAP.md, M1).
- Review the list of values the MP-SPDZ program opens (`mpc/mp-spdz/README.md`).
- Constant-time arithmetic in `fips204.rs`.
- More tower shapes in the networked path.
