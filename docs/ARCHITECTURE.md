# Architecture: one kernel, three layers

cairn serves two audiences with one signing core. A proof-of-stake chain and an organization
want the same thing from the cryptography (`T` of `N` parties produce one standard ML-DSA-65
signature, the key is never assembled) and differ in everything around it: what may be
signed, who is on the committee, and how clients ask.

| Layer | Crates | Knows about | Must not know about |
|---|---|---|---|
| 1. Kernel | `threshold-mldsa`, `cascade-tower`, `mpc-bridge`, `cairn-core` | Keys, shares, rounds, opaque message bytes, rosters with weights | Blocks, heights, chains, cloud APIs, approvals |
| 2. Policy | `cairn-policy` | What this party will sign | How signatures are made or transported |
| 3. Front ends | `cairn-gateway`, `cairn-sidecar` | One client protocol each | Which engine or policy is behind the signer |

`cairn-net` is the transport between parties. It carries the kernel's rounds and asks the
party's policy before revealing anything; it holds no rules of its own for the flat protocol.

## The three interfaces

**`cairn_core::ThresholdSigner`**: bytes in, signature out.

```rust
fn backend(&self) -> Backend;                       // Flat or Tower
fn public_key(&self) -> [u8; 1952];
fn sign(&mut self, message: &[u8]) -> Result<[u8; 3309], SignerError>;
fn reshare(&mut self, next: &Roster) -> Result<(), SignerError>;   // always Unsupported today
```

| Implementation | Backend | Where the parties are |
|---|---|---|
| `cairn_core::LocalFlat` | Flat | This process |
| `cairn_core::LocalTower` | Tower | This process |
| `cairn_sidecar::cluster::CommitteeSigner` | Flat | Separate processes or hosts, TLS |
| `cairn_sidecar::cluster::ClusterSigner` | Tower | Separate processes, TLS |
| `cairn_sidecar::TowerCertifier` | Tower | This process, with the certificate log |

**`cairn_policy::PolicyEngine`**: a party's own decision.

```rust
fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError>;
```

| Implementation | Rule |
|---|---|
| `PosCheckpointPolicy` | A well-formed checkpoint for this key, on a served chain, never below or conflicting with one already signed (state on disk before answering) |
| `Unrestricted` | Anything. Protects nothing by itself |

**`cairn_core::RosterProvider`**: who is on the committee, with weights. `StaticRoster` and
`FileRoster` (JSON, re-read on every call) exist. `Roster::flat_shape` says whether the flat
backend can serve a roster: only unweighted ones it has parameters for (up to six members).

## Choosing a backend

| | Flat | Tower |
|---|---|---|
| Committee size | 2 to 6, unweighted | Larger; stake-weighted assignment |
| Same message signed twice | Different signatures | Same signature |
| Hardening in this repository | TLS, pinned certificates, per-party policy, signed commitment sets, failover, metrics | In-process and loopback processes; fewer protections |

The determinism row is tested (`crates/cairn-core/tests/signer.rs`). It is the one place
the two audiences pull apart: accountability and deduplication are simpler with the tower,
latency and maturity favour the flat protocol.

## What is not there yet

- **Resharing and share refresh**: `reshare` returns `Unsupported` on every backend. See
  BLOCKERS.md.
- **An organization policy**: approvals, limits, roles. The trait is ready
  (`crates/cairn-net/tests/policy_plug.rs` runs a committee under a non-checkpoint rule); no
  such policy ships, and the `cairn` CLI always runs the checkpoint rules.
- **The networked tower nodes still check the checkpoint prefix themselves**
  (`cairn-net/src/node.rs`) instead of asking a `PolicyEngine`.
- **Roster providers for chains or directories**, and a path from a roster to a running
  committee: today key generation takes `T` and `N` directly.
- **Other front ends** (PKCS#11, KMIP, gRPC, peer-to-peer). `cairn-gateway` has the KMS API
  only, and it depends on `cairn-net` for its TLS listener.
