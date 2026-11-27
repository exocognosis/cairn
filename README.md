# cairn

[![CI](https://github.com/exocognosis/cairn/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/cairn/actions/workflows/ci.yml)
![Status: research preview](https://img.shields.io/badge/status-research%20preview-orange)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![FIPS 204 ML-DSA-65](https://img.shields.io/badge/FIPS%20204-ML--DSA--65-blue)

**A group signs with one ordinary post-quantum signature, and no member ever holds the key.**

cairn is a threshold signing system for ML-DSA-65 (FIPS 204, formerly Dilithium). A committee
of validators or of an organization's operators jointly produces a single standard 3,309-byte
signature, each member applying its own rules first. Any existing FIPS 204 verifier accepts
it: no new verifier, no proof system, no change on the verifying side.

## Two engines; use the committee

| | Committee (flat) | Tower |
|---|---|---|
| Use it for | **anything you intend to rely on** | research into larger signer sets |
| Members | 2 to 6, equal weight | 16 signers in 4 leaves, plus 4 root engines |
| Key generation | joint (`cairn dkg`): no machine ever holds the key | one trusted dealer |
| Secret computation | complete: nothing is stood in for | needs a three-party MPC; the tested one is semi-honest and the default is a clear-text stand-in |
| Latency across two hosts, about 180 ms apart | 1 to 6 s (2-of-3 to 3-of-5) | 6 s with the stand-in, 23 s with real MPC |
| Signature | valid ML-DSA-65, randomized | byte-identical to a deterministic FIPS 204 signer |

The committee is the path this project hardens for use. The tower stays as the mode that
reproduces the FIPS 204 signer exactly and as the place to study committees of committees.
Neither has had outside review ([What it is not, yet](#what-it-is-not-yet)). Sections from
"Why a tower" on describe the tower.

## Why it matters

Proof-of-stake chains compress thousands of validator votes into one small signature using BLS.
BLS falls to a quantum computer. Its standardized post-quantum replacement, ML-DSA, does not
aggregate: a thousand validators means a thousand 3.3 kB signatures, about 3.3 MB per block
for a light client to download and check.

cairn takes the other route. Instead of aggregating many signatures, the validators share one
key and compute one signature together. A light client, bridge or wallet verifies a checkpoint
with one 1,952-byte public key, one 3,309-byte signature and a stock library.

The hard part is that ML-DSA is hostile to this. Signing hashes a secret, rounds
non-linearly and retries about five times per signature, all of which must happen without any
party seeing the key. cairn's answer is a **committee tower**: small committees nested under a
small multi-party computation, so the expensive computation never has more than three parties.

## What works today

Each line is a test or a recorded run in this repository.

| Result | Evidence |
|---|---|
| **Standard output.** The signature is byte-identical to what a single FIPS 204 signer holding the whole key would produce. | Compared in every test path against a reference signer and RustCrypto `ml-dsa`. |
| **Unmodified verifiers accept it.** | `pqc-sidecar verify`, the `@exocognosis/pqc-sidecar-verify` npm package and RustCrypto all accept the certificate and reject a tampered one. |
| **It runs as separate machines.** 16 signer processes, 4 root engines and an MPC backend over mutually authenticated TLS. | Run across a Mac in the US and a server in Helsinki, 178 ms apart. |
| **A real MPC does the secret computation.** | MP-SPDZ, three parties, 103 signing attempts on Linux with no failure. |
| **A stock checkpoint daemon uses it unchanged.** | An unmodified `pqc-sidecar` signs live checkpoints through cairn by configuration alone. |
| **It has signed a real chain's blocks.** | An unmodified pqc-sidecar followed Cosmos Hub mainnet in light-client mode and a 3-of-4 committee with a jointly generated key signed two checkpoints (`scripts/real-chain-demo.sh`). |
| **Faults do not stall it.** Offline, stalled and misbehaving nodes are skipped or named and replaced. | Network tests with wall-clock deadlines. |
| **Measured cost.** About 21 s per checkpoint across two hosts with real MPC; 0.12 s on one machine with a stand-in backend. | [Benchmarks](#benchmarks). |

118 automated tests; `clippy` clean.

## What it is not, yet

cairn is a **research preview, not custody software**. For the committee engine the gaps are:
no outside review, a floating-point mask sampler, code that is not constant time, and a limit
of six equal members whose set cannot change without a new key. The tower adds three more:

1. **The MPC is semi-honest.** It protects the key from parties that follow the protocol, not
   from ones that deviate.
2. **Trust concentrates while signing.** At rest, 9 of 16 signers are needed to reach the key.
   During a signing session, two colluding root engines are enough.
3. **One dealer creates the key** in the tower design. (The newer committee protocol below
   generates its key jointly.)

Nothing here has had outside review. [Status and limits](#status-and-limits) has the full
list and [ROADMAP.md](ROADMAP.md) says what closing each gap takes.

## The committee engine

Recent work shows the secret mask does not have to be computed inside an MPC at all. cairn
implements the three-round protocol of *Efficient Threshold ML-DSA* (USENIX Security
2026) for one committee of up to six parties: no MPC backend, no root engines, and signatures
that the same unmodified verifiers accept. They are valid ML-DSA-65 signatures, but not the
ones a deterministic FIPS 204 signer would produce.

It runs as separate processes over mutual TLS, and a stock pqc-sidecar signs through it
(`stock_pqc_sidecar_signs_through_a_three_round_committee`). 100 certificates per row, one
Apple M3, each party its own process, injected round-trip time on every link:

| RTT | committee | one execution at a time: latency ms (mean / p50 / p95 / max) | two side by side |
|---|---|---|---|
| localhost | 2-of-3 | 42 / 38 / 88 / 174 | 45 / 38 / 89 / 115 |
| localhost | 3-of-4 | 129 / 118 / 290 / 413 | 181 / 128 / 424 / 635 |
| localhost | 3-of-5 | 370 / 335 / 1,005 / 1,489 | 466 / 337 / 991 / 1,332 |
| 50 ms | 2-of-3 | 277 / 277 / 559 / 978 | 207 / 159 / 452 / 517 |
| 50 ms | 3-of-4 | 407 / 355 / 1,226 / 1,409 | 318 / 231 / 671 / 890 |
| 50 ms | 3-of-5 | 563 / 561 / 1,127 / 1,405 | 725 / 521 / 1,626 / 3,337 |
| 180 ms | 2-of-3 | 823 / 791 / 1,992 / 3,149 | 610 / 421 / 1,453 / 2,081 |
| 180 ms | 3-of-4 | 922 / 906 / 2,265 / 3,647 | 712 / 516 / 1,227 / 2,022 |
| 180 ms | 3-of-5 | 1,243 / 1,134 / 2,836 / 3,412 | 1,131 / 816 / 2,439 / 3,168 |

Masks are sampled ahead of time, so a signing request costs two round trips per execution,
and about half of all executions end without a signature (2.0 to 2.3 executions per
certificate). Running two executions side by side (`serve-kms --parallel-attempts`, default
2) cuts mean latency by about a quarter for 2-of-3 and 3-of-4 once the link has delay; for
3-of-5 on this one shared machine it does not help, because the parties' CPU is the limit. A
certificate moves about 0.1, 0.6 and 1.9 MB per party for the three sizes. These rows use the
double-double mask sampler ([docs/SAMPLER.md](docs/SAMPLER.md)), which costs 15 to 120 ms
more than `f64` did here with every party on one laptop.

**Across two real hosts** (one party and the coordinator on a home connection in the US, the
others in Helsinki, 185 ms apart) it is slower than the injected-delay rows suggest, because
this protocol moves a lot of data and injected delay does not model that:

| committee | certs | latency s (mean / p50 / p95) | kB per party per cert |
|---|---|---|---|
| 2-of-3 | 50 | 1.02 / 0.76 / 2.33 | 86 |
| 3-of-4 | 50 | 3.90 / 3.22 / 9.41 | 544 |
| 3-of-5 | 20 | 6.30 / 6.24 / 11.66 | 1,872 |

A stock pqc-sidecar signed a live checkpoint through the cross-host 3-of-4 committee in about
3 s. That run predates the precomputed masks and side-by-side executions, which save round trips
but not the data transfer that dominated it; it has not been repeated. For comparison, the tower design took 21 s on a similar link with real MPC. These numbers
include all of the cryptography; there is nothing left to substitute.

```bash
./scripts/run_local_committee.sh --committee 3-of-4
```

```bash
cargo run --release -p cairn-sidecar -- mithril-demo --threshold 3 --parties 4
```

The committee generates its own key: `cairn dkg` runs the paper's distributed key generation,
so no machine ever holds the whole key (the local script uses it by default).

A party that sends a wrong response is identified from public values and excluded.

Safeguards an operator gets today: every party checks the checkpoint itself and will not sign
for another key, an unlisted chain, a lower height, or a second checkpoint at one height (kept
on disk across restarts); the KMS endpoint verifies AWS SigV4 request signatures and refuses to
listen beyond loopback without credentials; parties and the coordinator write audit logs.

**It is a prototype, not a secure implementation**: written from the paper without comparison
against the authors' code, floating-point sampling, not constant time, and measured across
hosts only once, on one link. Cost also rises steeply with the threshold, so small thresholds are the
practical range. [docs/PRODUCTION_PATH.md](docs/PRODUCTION_PATH.md) has the comparison and what
is missing; ARCHITECTURE.md section 10.7 has the protocol. Everything below describes the
original tower design, which remains the "exact FIPS 204 signer" mode.

## Try it in five minutes

Requires Rust 1.80 or newer on macOS or Linux.

```bash
git clone https://github.com/exocognosis/cairn.git && cd cairn && cargo test --workspace
```

```bash
cargo run --release -p cairn-sidecar -- demo --out out
```

The second command needs nothing else installed. It deals a 16-signer tower, signs a sample
checkpoint, writes `out/00000000000000001200.pqcc` and `out/public_key.hex`, then verifies the
file from disk with RustCrypto `ml-dsa` and confirms a tampered copy is rejected. Check the
certificate again at any time:

```bash
cargo run --release -p cairn-sidecar -- verify --certificate out/00000000000000001200.pqcc --public-key out/public_key.hex
```

In this demo all sixteen signers run inside one process. To watch 21 separate processes do it
over TLS, run `./scripts/run_local_cluster.sh`. [Running it](#running-it) covers the cluster,
the live sidecar flow and two-host deployment.

## Where to read next

| If you want | Read |
|---|---|
| The idea and the evidence | this page |
| Terms such as *leaf*, *root engine*, *attempt*, *share compression* | [docs/GLOSSARY.md](docs/GLOSSARY.md) |
| Short answers to common questions | [docs/FAQ.md](docs/FAQ.md) |
| The protocol, message by message | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Why each design choice was made (65 entries) | [DECISIONS.md](DECISIONS.md) |
| How the kernel, policy and front-end layers fit, and what each may know | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Signing for an organization: approvals instead of checkpoints | [docs/ORG_POLICY.md](docs/ORG_POLICY.md) |
| Attaching any chain or organization: policy hooks, roster commands, `cairn sign` | [docs/HOOKS.md](docs/HOOKS.md) |
| Everything that still blocks production use, with status | [docs/BLOCKERS.md](docs/BLOCKERS.md) |
| Backup, certificate rotation, standby coordinator, monitoring, upgrades | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Why cairn's additions to the protocol should be safe, and where that argument stops | [docs/SECURITY_ARGUMENT.md](docs/SECURITY_ARGUMENT.md) |
| How exact and how constant-time the mask sampler is | [docs/SAMPLER.md](docs/SAMPLER.md) |
| What is planned and what funding would buy | [ROADMAP.md](ROADMAP.md) |
| The gap to a production BLS replacement, and recent related work | [docs/PRODUCTION_PATH.md](docs/PRODUCTION_PATH.md) |
| Running it on two machines | [DEPLOY_SPLIT.md](DEPLOY_SPLIT.md) |
| The MP-SPDZ circuit | [mpc/mp-spdz/README.md](mpc/mp-spdz/README.md) |
| Contributing or reporting a vulnerability | [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) |

## Why a tower: the N = 6 wall

ML-DSA signing is hostile to MPC. `ExpandMask` is SHAKE256 over a secret seed, `HighBits` and
`LowBits` are non-linear rounding, and Fiat-Shamir with aborts repeats the whole computation
about five times per signature. The predecessor prototype
(lattice-aggregation, by the same author, not yet public) ran the exact FIPS
204 mask inside a malicious-secure dishonest-majority MPC: N = 4 (3-of-4) costs 28 GB of
traffic, N = 5 costs 55 GB, and N = 6 failed on a 16 GiB host. One MPC over a validator set is
not an option.

cairn never runs an interactive committee larger than six (`MAX_COMMITTEE`), and in v2 the one
MPC that evaluates the non-linear functions has exactly three parties:

```
 leaf 1 (3-of-4)   leaf 2 (3-of-4)   leaf 3 (3-of-4)   leaf 4 (3-of-4)      16 signer nodes
  s  s  s  s        s  s  s  s        s  s  s  s        s  s  s  s          leaf_i/signer_j
   \  |  /           \  |  /           \  |  /
    additive sub-shares, point to point (9 active signers x 3 engines)
        \               |               /
       root_1  ------ root_2 ------ root_3        (root_4: spare)           root engine nodes
          \             |             /
           three-party MPC backend (IPC)          ExpandMask, HighBits/LowBits, abort checks, MakeHint
```

## How a signature is made (v2)

1. **Prepare.** The coordinator (`cairn serve-kms`) announces the message. Every live signer and
   root engine answers within a wall-clock deadline. Nodes refuse anything that is not a
   pqc-sidecar checkpoint message.
2. **Share compression.** The key is nested-Shamir shared: 3-of-4 across leaves, each leaf's
   share 3-of-4 across its signers. Each of the nine active signers multiplies its share by
   `Λ_i · λ_j` (root coefficient of its leaf times its own leaf coefficient), which makes the
   nine values a plain additive sharing of the key. It splits that value into three uniform
   sub-shares and sends one to each active root engine, directly. Each engine adds what it
   received. No leaf secret and no key is ever assembled, and the coordinator carries no share
   material.
3. **Share check.** Each engine publishes `A·a1 + a2` for every sub-share it got. The three
   values for a signer must add up to that signer's public verification share times its weight,
   so a signer that deals a wrong share is named.
4. **Attempts.** Each engine plays one party of the MPC backend: the mask phase opens `c~`, the
   engine does the linear step on its own share (`z_k = y_k + c·s1_k`, `r_k = A·y_k − c·s2_k`),
   and the response phase opens either "rejected" or the hint and `z`. On rejection the attempt
   counter advances (`kappa += 5`, exactly FIPS 204) and only the two MPC phases repeat.
5. **Faults.** A silent peer costs one deadline and is skipped. A named peer is excluded and the
   session is re-formed at the same `kappa`, so the signature is still the deterministic one.

## What the bounds cover

The corruption bounds of the tower come from the `CertTowers` Lean 4 library (99 theorems, no
`sorry`; private, not vendored here). `cascade-tower` evaluates the closed forms:

| Property | 3-of-4 × 3-of-4 | Theorem |
|---|---|---|
| Fewest signers whose stored shares give the key | 9 of 16 (`∏ t_j`) | `CertTowers.Access.minAuth_isLeast` |
| Fewest offline signers that can block | 4 of 16 (`∏ (k_j − t_j + 1)`) | `CertTowers.Access.minBlock_isLeast` |
| Pr[9-set compromised], i.i.d. corruption 10% | ≈ 2 × 10⁻⁷ | `CertTowers.ThresholdTree.rootProb_list` |

These hold for the **signers' long-term shares**. They are not the whole story once signing is
distributed as in v2:

- **Secrecy while signing** is bounded by the root MPC. The three active engines jointly hold
  the key for one session. Three colluding engines always reconstruct it; with an
  honest-majority protocol (`replicated-field-party.x`) two do. Engines are separate nodes, so
  this is a second, smaller trust set next to the 16 signers. Closing that gap means each leaf
  committee jointly playing its root party, which is still open (ARCHITECTURE.md §11).
- **Liveness** needs, besides no blocking set of signers, three of the four root engines.
- **Attribution** of a bad sub-share rests on the engines' published check values: a lying
  engine can make an honest signer look wrong.

A unit test checks the two extremal bounds against brute force over all 65,536 signer subsets,
and a property test checks the compression: engine shares sum to the key, and no single view
(an engine, a signer, the coordinator) holds the key or any leaf's share of it.

## Status and limits

| | |
|---|---|
| **Works, tested** | Run across two hosts (US Mac and a Helsinki server, 178 ms apart) with real MP-SPDZ and a stock pqc-sidecar. 16 signer processes, 4 root-engine processes and an MPC worker process sign over mutually authenticated TLS with wall-clock deadlines. A stock pqc-sidecar daemon calls `GetPublicKey` and `Sign` on the cluster and writes a certificate that unmodified verifiers accept. Output is byte-identical to a single deterministic FIPS 204 signer. Offline, stalled and deviating peers are skipped or named. |
| **MPC backend** | The non-linear half of every attempt runs in a three-party backend behind an IPC bridge. Tests and the benchmark table use `cairn mpc-worker`, a **clear-text reference worker** (that process sees the signing seed and every rejected candidate). A real MP-SPDZ backend (`mpc/mp-spdz/`, `replicated-field-party.x`) passes the same bridge tests and the live sidecar flow on one machine. It is **semi-honest** only: the malicious-security variant runs only at a reduced security parameter, and the three MPC parties have only ever run together on one host (macOS and Linux). See [mpc/mp-spdz/README.md](mpc/mp-spdz/README.md). |
| **Trust during signing** | Share compression hands the key, for the length of a session, to three root engines as a 3-party additive sharing. The 9-of-16 bound describes shares at rest. While signing, the bound is the root MPC's: with an honest-majority three-party protocol, **two colluding root engines learn the key**. See "What the bounds cover". |
| **Links are mutually authenticated** | Every node link is TLS 1.3 with client certificates. A certificate is trusted because its fingerprint is pinned in the node's own table, with no authority; a node only answers pinned peers and drops frames whose sender is not the certificate's node. Certificates can be rotated and revoked on a running committee, and each machine can make its own (`cairn tls-rotate`). |
| **Trusted dealer** | The key is generated by a dealer (`cairn keygen`) and shared down the tower. |
| **Unreviewed** | No security proof of the composed protocol, no external review, not constant time. |

So: v2 demonstrates the distributed execution path end to end and pins down every interface.
It is not threshold custody: the verified MPC backend is semi-honest, session-time trust sits
with the root engines, and one dealer creates every key.

## Running it

Requires Rust 1.80+. The external-verifier and live checks also need Node 20+ and a pqc-sidecar
checkout next to this repository.

```bash
cargo test --workspace
```

```bash
./scripts/setup-verifiers.sh
```

```bash
CAIRN_REQUIRE_EXTERNAL_VERIFIERS=1 cargo test --workspace
```

`setup-verifiers.sh` builds the pqc-sidecar checkout as is (into `target/`; nothing is written
to the checkout) and installs the published `@exocognosis/pqc-sidecar-verify`. Without it the
tests that need them print `SKIPPED` and everything else still runs, including the multi-process
cluster and the RustCrypto `ml-dsa` checks.

### A local cluster of separate processes

```bash
./scripts/run_local_cluster.sh
```

This starts 16 signer nodes, 4 root-engine nodes, the reference MPC worker and `cairn serve-kms`
on loopback (`--rtt-ms 50` injects WAN latency, `--fault leaf_1/signer_1=stall` scripts a fault).
One node by hand looks like:

```bash
target/release/cairn node --role signer --id leaf_2/signer_3 --bind 127.0.0.1:7106 --peers keys/peers.json --group keys/group.bin --tls keys/tls --share keys/leaf_2_signer_3.share
```

### Live: an unmodified pqc-sidecar signing through the cluster

```bash
./scripts/live-sidecar-e2e.sh
```

The script starts the cluster and a CometBFT RPC stand-in (`cairn mock-chain`), then runs the
stock pqc-sidecar binary with its `aws_kms` backend pointed at `serve-kms`. The sidecar calls
`GetPublicKey`, then runs as a daemon, calls `Sign` for the checkpoint at height 100 and writes
the certificate; the script verifies it with `pqc-sidecar verify` and checks that a tampered copy
is rejected. The same flow runs under `cargo test` as
`stock_pqc_sidecar_signs_a_live_checkpoint_through_the_cluster`. pqc-sidecar signs with
`MessageType = RAW`; the endpoint implements that mode only.

The sidecar configuration is the stock one:

```toml
[signer]
backend = "aws_kms"
aws_kms_key_id = "alias/cairn-tower"
aws_region = "us-east-1"
aws_endpoint_url = "http://127.0.0.1:8200"
public_key_file = "public_key.hex"

[checkpoint]
interval = 100   # checkpoint cadence: every K finalized blocks
```

### Commands

| Command | What it does |
|---|---|
| `cairn demo` | One process: deal a tower, sign a sample checkpoint, write and verify the certificate. |
| `cairn verify --certificate <f> --public-key <f>` | Verify a `.pqcc` certificate with RustCrypto `ml-dsa`. |
| `cairn keygen --out <dir>` | Create the key shares, address book and TLS certificates for a cluster. |
| `cairn node --role signer\|root ...` | Run one signer or one root engine. |
| `cairn mpc-worker --socket-dir <dir>` | Run the stand-in MPC backend (clear text, for testing). |
| `cairn serve-kms [--backend flat\|tower] ...` | Coordinate signing and expose it as a KMS-compatible endpoint. `flat` is the three-round committee (randomized signatures), `tower` the two-tier protocol (deterministic). |
| `cairn mock-chain` | A minimal CometBFT RPC stand-in for end-to-end runs without a chain. |
| `cairn identity`, `cairn dkg-party`, `cairn dkg` | Distributed key generation for a flat committee: no dealer. |
| `cairn node --role party` | A committee party (three-round protocol). `cairn keygen --committee` is the dealer shortcut for tests. |
| `cairn cluster-bench`, `committee-bench`, `remote-bench`, `bench` | Benchmarks: tower processes, committee processes, a running cluster, single process. |

`cairn` with no arguments prints every flag.

## Benchmarks

```bash
cargo run --release -p cairn-sidecar -- cluster-bench --signatures 100 --rtt-ms 0,50 --json target/cluster-bench.json
```

Each scenario spawns a fresh cluster of 21 OS processes on one Apple M3 (16 signers, 4 root
engines, 1 reference MPC worker), with the coordinator in the benchmark process. 100 certificates
per row. "RTT" is injected latency on every link (half in each direction).

| RTT | scenario | latency ms (mean / p50 / p95 / max) | rejected attempts (mean) | fault retries | bytes per signer | bytes per engine | total kB per cert | exchanges |
|---|---|---|---|---|---|---|---|---|
| localhost | healthy | 124 / 107 / 253 / 430 | 4.60 | 0.00 | 35,109 | 91,590 | 593 | 72 |
| localhost | one-offline (stalled) | 1,134 / 1,107 / 1,256 / 1,503 | 5.23 | 0.00 | 35,109 | 91,755 | 593 | 74 |
| localhost | one-malicious | 150 / 138 / 252 / 537 | 4.55 | 1.00 | 66,351 | 147,648 | 1,079 | 105 |
| 50 ms | healthy | 1,030 / 844 / 2,104 / 3,660 | 4.48 | 0.00 | 35,109 | 91,555 | 593 | 71 |
| 50 ms | one-offline (stalled) | 1,924 / 1,792 / 3,028 / 4,472 | 4.09 | 0.00 | 35,109 | 91,455 | 592 | 68 |
| 50 ms | one-malicious | 1,217 / 1,025 / 2,236 / 2,980 | 3.63 | 1.00 | 66,351 | 147,404 | 1,079 | 100 |

All links are mutually authenticated TLS 1.3 over pooled connections.

How to read this:

- **The MPC backend in this table is the clear-text reference worker**, which costs a few
  milliseconds. The table measures everything around the MPC: transport, share compression,
  checks, retries. The MPC itself is the next table.
- **Latency is wall-clock at the coordinator.** A session costs six round trips of setup and
  teardown (prepare, deal with its nested signer-to-engine hop, collect, install, erase) and two
  per attempt, so at 50 ms RTT a certificate costs about `(6 + 2 · attempts) × 50 ms` plus
  compute, with a long tail from the rejection distribution. The injected delay is a sleep per
  send: it models neither handshakes nor congestion windows, so read the two-host numbers below
  for what a WAN really costs.
- **One-offline** is a *stalled* signer (accepts connections, never answers), reinstated before
  every certificate so the fault is paid every time: it adds one full round deadline (1 s here).
  A node that is down is refused at once and costs nothing; in normal operation the stalled
  node is excluded after the first certificate.
- **One-malicious** is a signer dealing a wrong share at every certificate: it is named at the
  share check and the session is re-formed, one retry.
- **Bytes** are frame bytes before TLS record overhead. A signer's are its coordinator link plus three sub-shares
  (about 11 kB each); they do not grow with the number of attempts. An engine's are dominated by
  the share check (nine 6 kB values) and the opened `z` of the accepted attempt.

### With the MP-SPDZ backend

The same IPC protocol is served by `mpc/mp-spdz/` (three `replicated-field-party.x` processes,
semi-honest, honest majority, over the field `Z_q`). On the same machine, three parties on
loopback over TLS, per attempt and per party (MP-SPDZ's own counters):

| Phase | Time | Data sent per party | Rounds |
|---|---|---|---|
| mask (`ExpandMask`, `A·y`, `HighBits`, `c~`) | 1.2 s (1.8 s with process start) | 85 MB | about 1,940 |
| response (checks, `LowBits`, `MakeHint`) | 0.33 s (0.7 s with process start) | 15.6 MB | about 90 |

So one attempt is about 2.5 s and 100 MB per party on loopback, and a certificate (5.1 attempts
on average) about 13 s and 0.5 GB per party. With about 2,000 rounds the mask phase is
latency-bound once the parties are on different hosts: at 50 ms RTT expect on the order of 100 s
per attempt. That case is still unmeasured; the two-host run below kept all three parties on
one server.

What was run with this backend on this machine: the `mpc-bridge` integration tests (the
16-signer tower's signature byte-identical to the FIPS 204 reference, the three-holder flow, the
fault cases) and the live flow `CAIRN_MPC_SOCKET_DIR=<dir> scripts/live-sidecar-e2e.sh` (stock
pqc-sidecar, 20 node processes over TCP, MP-SPDZ as the root MPC, certificate verified). pqc-sidecar's
KMS client times out a call after 5 s and retries; the endpoint answers a retry from the finished
signature, which is sound because signing is deterministic.

### Across two hosts

One run, on 2026-11-24: leaf 1 (four signers), the coordinator (`cairn serve-kms`) and the stock
pqc-sidecar on an Apple M3 in the US; leaves 2 to 4 (twelve signers), four root engines, the MPC
backend and `cairn mock-chain` on a Hetzner `cpx42` (8 shared vCPU, 16 GB) in Helsinki. Measured
round trip 178 ms. Node links are mutual TLS, carried through SSH port forwards so that no
port was opened on the server (`scripts/split-host/`).

| MPC backend | certs | latency s (mean / p50 / p95 / max) | rejected attempts (mean) |
|---|---|---|---|
| reference worker, one connection per exchange | 30 | 16.2 / 15.3 / 26.3 / 41.6 | 4.43 |
| reference worker, pooled connections | 50 | 6.0 / 5.8 / 11.8 / 13.2 | 3.56 |
| MP-SPDZ `replicated-field-party.x`, pooled | 15 | 21.4 / 17.7 / 45.7 / 63.4 | 4.87 |

MP-SPDZ on that server, three parties on its loopback, over 103 attempts with no failure: mask
phase 1.72 s per attempt (1.48 s inside MP-SPDZ, 85 MB sent per party, 1,943 rounds), response
phase 0.51 s (0.33 s, 15.7 MB, 93 rounds).

Repeated on 2026-11-26 with version 0.7.0, same hosts and layout (a new `cpx42`, round trip
176 ms), to see what the tower's added checks cost (signers bound to the message they
approved, root engines cross-signing each session):

| MPC backend | certs | latency s (mean / p50 / p95 / max) | rejected attempts (mean) |
|---|---|---|---|
| reference worker | 50 | 6.2 / 5.4 / 10.3 / 16.0 | 3.96 |
| MP-SPDZ `replicated-field-party.x` | 15 | 22.9 / 23.0 / 37.2 / 59.5 | 3.13 |

No measurable cost: both rows are within the spread of the first run. MP-SPDZ over 73
attempts with no failure (`scripts/split-host/mpc-phases.py` on the bridge log): mask phase
3.14 s per attempt (2.82 s inside MP-SPDZ, 85.1 MB sent per party, 1,942 rounds), response
phase 0.73 s (0.47 s, 15.6 MB, 87 rounds). The MPC phases were slower than on the first
server at the same data and round counts, which points at the shared vCPUs, not the code. The
stock pqc-sidecar signed height 100 in 14 s (reference) and 58 s (MP-SPDZ); `pqc-sidecar
verify` accepted both certificates and rejected a tampered copy of each.

In both configurations of the first run the stock pqc-sidecar on the Mac then called `GetPublicKey` and `Sign`,
wrote the height-100 certificate, and `pqc-sidecar verify` accepted it; with MP-SPDZ a tampered
copy was also checked and rejected.

What this run showed:

- **Connection reuse matters more than anything else on a WAN.** The first measurement, 16 s,
  was the transport opening a TCP connection and a TLS session for every exchange. Keeping
  connections open cut it to 6 s. The injected-delay table above cannot show this effect.
- **The remaining 6 s is mostly session setup, not attempts.** An attempt is two exchanges
  (about 0.4 s). The rest is setup: the share check and the opened `z` move about 0.3 MB over
  connections that have been idle. That split is an estimate from the totals, not a separate
  measurement. Reusing the engines' shares across checkpoints would remove most of it (D-41).
- **With real MPC the attempts dominate**: about 3 s each, 2.2 s of it MP-SPDZ.
- **Limits of this run:** one run, small samples, shared vCPUs, all three MPC parties on one
  host (so the 1,943 MPC rounds paid no WAN latency), semi-honest MPC, a chain stand-in, and
  an SSH tunnel under the TLS links.

The single-process harness (`cairn bench`) is still there for protocol-only numbers; its v1
table is in the git history.

## Roadmap and support

The next milestones, in order, each with an acceptance test in [ROADMAP.md](ROADMAP.md):

1. MPC parties on three separate hosts, measured.
2. A malicious-secure root MPC.
3. Leaf committees controlling the root parties, so the 9-of-16 bound holds during signing.
4. Dealerless key generation and share refresh.
5. External review and a written security argument.
6. A testnet pilot with a real CometBFT chain.

This is independent research. If your organisation funds post-quantum infrastructure, runs
validators, or wants a pilot, [ROADMAP.md](ROADMAP.md) lists what each milestone needs and
delivers. To get in touch, write to
<rick@dytallix.com> or open an issue on this repository.

## Repository layout

| Path | Contents |
|---|---|
| `crates/threshold-mldsa` | FIPS 204 internals, nested Shamir dealing, share compression (`flatten`), the sealed MPC boundary and `AttemptEngine`, the in-process committee state machines. |
| `crates/cascade-tower` | Tower shape and bounds, stake-weighted epoch assignment, the in-process two-tier `Tower`. |
| `crates/mpc-bridge` | IPC protocol to the three-party backend (Unix sockets, binary frames), `IpcEngine` behind `AttemptEngine`, the reference worker. |
| `crates/cairn-core` | The shared kernel interface: `ThresholdSigner` over both engines, committee rosters, standard verification. No chain or enterprise types. |
| `crates/cairn-policy` | What a party agrees to sign: the `PolicyEngine` trait and the proof-of-stake checkpoint rules. |
| `crates/cairn-net` | Framed transport over mutual TLS with deadlines, party, signer and root-engine nodes, the session coordinators. |
| `crates/cairn-gateway` | Client front ends over any `ThresholdSigner`: the KMS-compatible endpoint and SigV4 checking. |
| `crates/cairn-sidecar` | `.pqcc` v2 certificates, networked signers, process launcher, benchmarks, the `cairn` CLI. |
| `mpc/mp-spdz` | MP-SPDZ program and launcher for the same IPC protocol. |
| `scripts` | Verifier setup, local cluster, live end-to-end run. |

## Hard invariants

- In the tower design, signatures are FIPS 204 ML-DSA-65 with the exact SHAKE256 `ExpandMask`
  (never random nonce sampling; the three-round prototype is the documented exception), encodings are standard (pk 1,952 bytes, signature 3,309 bytes), and no
  verifier is modified. Every path (in-process tower, IPC engine, TCP cluster of processes) is
  tested byte-for-byte against a single-key deterministic signer and RustCrypto `ml-dsa`.
- Every interactive committee has N ≤ 6; the root MPC has N = 3.
- A rejected attempt opens `c~` and one bit. No `z` share, hint, or failing bound is revealed.
- Nodes sign only pqc-sidecar checkpoint messages; the cadence is the sidecar's
  `checkpoint.interval`.

## Citing

See [CITATION.cff](CITATION.cff). cairn builds on lattice-aggregation, the predecessor
prototype by the same author, which is not yet public: its measurements are quoted above and
the helper section of the MP-SPDZ program here is adapted from it. cairn integrates with
PQC Sidecar, whose daemon is also not public; its certificate format and verifier are, as
[pqc-sidecar-verify](https://github.com/exocognosis/pqc-sidecar-verify). Without the daemon
the live sidecar tests print `SKIPPED`; everything else runs.

## License

[MIT](LICENSE). It is research code with no warranty: read [Status and limits](#status-and-limits)
before relying on it for anything.
