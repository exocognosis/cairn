# Architecture

This document specifies the cairn signing protocol. Sections 1 to 9 cover the in-process
protocol of v1; section 10 covers distributed execution (v2); section 11 lists what is open.
Section 1 onward: keys, the MPC boundary, the per-attempt
state machine at both tiers, retry synchronization, fault handling, and the path to a `.pqcc`
certificate. Section numbers of FIPS 204 algorithms are given where the code follows them.

## 1. Objects

| Object | Where | Meaning |
|---|---|---|
| `Gadget {t, n}` | `threshold-mldsa::keys` | One tier, `t`-of-`n`, `n ≤ 6` (`MAX_COMMITTEE`). |
| `Path` | `keys` | Position in the tower, root first, 1-based. `[2,3]` is signer 3 of leaf 2; `[2]` is leaf 2; `[]` is the root. |
| `KeyShare` | `keys` | A signer's nested Shamir share of `(s1, s2, K)` over `Z_q`. Zeroized on drop, never serialized. |
| `GroupPublic` | `keys` | Standard public key `pk`, `rho`, `tr`, `t0`, tower shape, per-signer verification shares `T_p = A·s1_p + s2_p`, per-signer seed-share commitments. |
| `Active` | `keys` | Tree of the signers taking part in one attempt. Determines every Lagrange weight. |
| `Sealed<T>` | `engine` | A value inside the MPC boundary. Coordinators can route, merge and split it; only an engine can open it. |
| `AttemptEngine` | `engine` | The non-linear half of an attempt (two phases). |
| `Party` | `party` | A participant of a committee: `Signer`, or a `Committee` acting as one party of its parent. |

### Keys

The dealer runs FIPS 204 `KeyGen_internal` (Algorithm 6) on a seed, then shares the vector
`s1 ‖ s2 ‖ K` (2,848 field elements; the 32 bytes of `K` are one element each) with Shamir over
`Z_q`, `q = 8380417`, once per tier: 3-of-4 across the leaves, then each leaf's share 3-of-4
across its signers. The public key is the ordinary 1,952-byte encoding, so the tower's key is
indistinguishable from a single signer's.

For an active set, signer `p` has weight `w_p = ∏ λ` (the Lagrange coefficient at zero of each
committee on its path, for that committee's active children). `Σ w_p · share_p` is the secret.
`Active::weights` computes this; a unit test reconstructs `s1` and `K` through it.

## 2. Trust boundary

One ML-DSA attempt splits into a linear and a non-linear part.

**Linear, done by each signer on its own share** (`party::Signer::respond`):

```
z_p = y_p + c · (w_p · s1_p)
r_p = A · y_p − c · (w_p · s2_p)
```

where `y_p` is the signer's additive share of the mask. Summed over the active signers these are
`z = y + c·s1` and `r = w − c·s2`.

**Non-linear, behind `AttemptEngine`:**

| Phase | Inputs (sealed) | Computes | Opens |
|---|---|---|---|
| `mask_phase` | seed shares | `K`; `rho'' = H(K ‖ 0³² ‖ mu)`; `y = ExpandMask(rho'', kappa)` (Alg. 34); `w = A·y`; `c~ = H(mu ‖ w1Encode(HighBits(w)))` | `c~`. `y` stays sealed. |
| `response_phase` | `(z_p, r_p)` per signer | sums; per-signer check `A·z_p − r_p = c·w_p·T_p`; mask check `‖r − w‖∞ ≤ β`; the four abort conditions of Alg. 7 (`‖z‖∞`, `‖LowBits(r)‖∞`, `‖c·t0‖∞`, hint weight ≤ ω = 55); `MakeHint` | accept bit; on accept the hint `h` and a digest of each `z_p`. |

`TrustedEngine` implements both phases in the clear, in process. **It is an ideal functionality,
not a secure computation**, and whoever runs it holds the seed for the duration of a phase. The
real backend this interface is shaped for is the MP-SPDZ program `mldsa65_sign_attempt` of the
lattice-aggregation prototype, which has the same two phases (it opens `c~`, then the accept
bit and, on accept, `z` and `h`).

`Sealed` enforces the boundary in the types (no accessor outside `engine`; `engine_open` is for
engine implementations), not in memory: in v1 a sealed value is plain data in the same process.

## 3. Rounds of one attempt

An attempt is identified by `AttemptCtx {session, attempt, retry, mu}`, where
`session = SHAKE256("cairn/session/v1" ‖ pk ‖ mu ‖ attempt ‖ retry)`. Every message carries a
`Header {version, session, attempt, retry, sender}`. Messages are `bincode`-encoded
(`protocol::Message`).

The same four rounds run at each tier. In the leaf tier the parties are signers; in the root
tier the parties are leaf committees, and a leaf's message is its coordinator's relay of what
its members sent.

| # | Round | Signer sends | Committee does |
|---|---|---|---|
| 1 | `Commitment` | participation binding `H("cairn/participate/v1" ‖ session ‖ path ‖ seed_commitment_p)` | Takes the first `t` live members that answer; checks each binding; fixes the active set, hence all weights. Broadcasts the active sub-tree. |
| — | engine `mask_phase` | sealed seed share | Root only: opens `c~`, hands the sealed mask down; each committee re-shares its mask share additively among its active children (`Sealed::split`). |
| 2 | `Challenge` | echo of `c~` | Checks every echo equals the opened `c~`. |
| 3 | `MaskedResponse` | hiding commitment `H("cairn/z-commit/v1" ‖ session ‖ path ‖ z_p ‖ salt)`; sealed `(z_p, r_p)` to the engine | Collects commitments, merges sealed parts upward. |
| — | engine `response_phase` | | Root only: verdict. |
| 4 | `HintCarry` | on reject: an empty acknowledgement, and erases `y_p`, `z_p`. On accept: opening `(z_p, salt)` | Each committee checks its own signers' openings against their commitments and relays them with the hint. The root checks each opening against the engine's digest, sums `z`, and encodes `sigma = c~ ‖ z ‖ h` (Alg. 26). |

The assembled signature is verified with RustCrypto `ml-dsa` before it is returned.

### State machine (one signer)

```
Idle ──commit──▶ Committed ──challenge(y_p, c~)──▶ Challenged ──respond──▶ Responded
  ▲                                                                           │
  │                    open(reject): erase, ack                               │
  └───────────────────────────────────────────────────────────────────────────┤
  └──────────────── open(accept): reveal (z_p, salt), erase ──────────────────┘
any state ──reset (fault abort)──▶ Idle, attempt state erased
```

A committee is the same machine over its children, plus the per-round checks above.

## 4. Rejection-loop safety

For a rejected attempt the public transcript holds: the active set, `c~` (a hash of public data
and `HighBits(w)`), hiding commitments to `z_p`, and the single bit "rejected". Not opened: any
`z_p`, the hint, `w`, the low bits, or which of the four bounds failed (`TrustedEngine` maps all
four to one `Verdict::Reject`). Signers zeroize `y_p` and `z_p` on the reject acknowledgement.
`tests/committee.rs::rejected_attempts_open_nothing` and the tower test assert this on recorded
transcripts.

The engine's mask-consistency check (`‖r − w‖∞ ≤ β`) depends only on whether the signers used
the masks they were given, never on the secret-dependent outcome, so running it before the
verdict leaks nothing.

Opening `z_p` on accept is safe: `y_p` is a uniform additive share, so each `z_p` is uniform and
only their sum, the public `z`, is determined.

## 5. Retry synchronization

Every transition is a function of broadcast data, so all honest nodes stay in step without a
clock or leader election.

| Event | Next attempt |
|---|---|
| Rejection (`Verdict::Reject`) | `attempt += 1`, so `kappa = attempt · L` advances by `L = 5` exactly as in FIPS 204. Same signing set. |
| Attributed fault (`Abort {fault}` naming a path) | `retry += 1`; the culprit is excluded for the rest of the session; same `kappa`. |
| Unattributed fault | `retry += 1`; one candidate that a spare can cover is suspended, in rotation (`Party::probe`); same `kappa`. |
| Silent at round 1 | No abort at all: the committee proceeds with its other members and stops waiting for the silent one. |

Repeating a `kappa` after a fault is sound in the deterministic variant: `y`, hence `c~` and
`z`, are functions of `(K, mu, kappa)` only. A retry recomputes the same values under a fresh
additive sharing, so a partial set of openings from the aborted run is a set of uniform values.

Limits (`SignPolicy`): 512 rejections, 16 fault retries, per-round timeout 2 s.

## 6. Faults and identifiable abort

| Deviation | Detected by | Attribution |
|---|---|---|
| Offline, or silent in a round | round timeout | signer path |
| Wrong participation binding | committee, round 1 | signer path |
| Echoes a different `c~` | committee, round 2 | signer path |
| Opening does not match its commitment | committee, round 4 | signer path |
| Opens a `z_p` other than the one given to the engine | root, digest comparison | signer path |
| Inconsistent `(z_p, r_p)` | engine, verification-share check | signer path |
| Wrong seed share | engine, dealt commitment | signer path |
| Uses a different mask share | engine, `‖r − w‖∞` | **none**; resolved by rotation |
| A whole leaf below its threshold | root, round 1 | leaf path; the root uses its spare leaf |

Liveness holds while the offline or excluded signers are not a blocking set: any 3 of 16, and
many larger sets. Below the root threshold, `sign` returns `SignError::QuorumLost` with the
fault list; it never hangs. `Tower::reinstate` (called by the certifier every
`reinstate_every` signatures) lets excluded signers back in.

The mask-share case cannot be attributed without separating `c·s1_p` from `y_p`, which would
need a verification share of `s1_p` alone and that would leak it. v1 handles it by rotation: at
most `n` extra attempts at the root.

## 7. Tower composition

`Committee<P: Party>` is itself a `Party`, so the tower is `Committee<Committee<Signer>>` and
the recursion carries every round. The tiers differ in one thing: only the root invokes the
engine. A leaf committee's tier work is linear (re-sharing a mask share, collecting response
shares).

Corruption bounds for a shape `[(k_1,t_1), …, (k_L,t_L)]` (`cascade-tower::params`):

- forge: `∏ t_j` signers (`CertTowers.Access.minAuth_isLeast`);
- block: `∏ (k_j − t_j + 1)` signers (`CertTowers.Access.minBlock_isLeast`);
- i.i.d. corruption `f`: root compromise probability is the binomial tail `Pr[Bin(k,·) ≥ t]`
  iterated from the leaves up (`CertTowers.ThresholdTree.rootProb_cons`, `rootProb_list`).

### Epoch assignment

`assignment::assign(epoch, epoch_seed, validators, params)` is deterministic: validators are
sorted by id; a SHAKE256 stream keyed by the epoch, seed, shape and validator set draws 16 seats
without replacement, each draw proportional to remaining stake (unbiased rejection sampling);
the chosen validators are dealt across the leaves in snake order of descending stake.
`Assignment::exposure(corrupt)` reports whether a given corrupt set can forge or block.

## 8. From checkpoint to certificate

```
finalized block ──▶ Checkpoint ──▶ M = "pqc-sidecar/checkpoint/v2" ‖ chain ‖ epoch ‖ height
                                        ‖ block_hash ‖ finality_commitment ‖ key_id
                 ──▶ Tower::sign(M) ──▶ 3,309-byte signature ──▶ Certificate (.pqcc v2)
```

`cairn-sidecar::certificate` implements pqc-sidecar's `FORMAT.md` version 2. Two ways in:

- **Library:** `TowerCertifier::certify` refuses heights that are not multiples of the
  checkpoint interval, signs, self-verifies, and `write_certificate` writes
  `<height:020>.pqcc` atomically without overwriting.
- **Unmodified pqc-sidecar:** `kms::serve` implements `TrentService.GetPublicKey` and
  `TrentService.Sign` (`RAW`, `ML_DSA_SHAKE_256`). The sidecar's `aws_kms` backend, pointed at it
  with `aws_endpoint_url`, signs every checkpoint through the tower. Cadence, finality checks and
  certificate writing remain the sidecar's.

KMS `Sign` is specified as hedged ML-DSA; the tower returns the deterministic variant. Both are
valid FIPS 204 signatures and verifiers cannot tell them apart.

## 9. Formal links

The Lean 4 sources (`CertTowers`, 99 theorems, no `sorry`, standard axioms) live in the private
research tree of the lattice-aggregation repository and are marked not for publication, so they
are cited by theorem name and not copied. `cascade-tower` evaluates their statements and checks
the two extremal bounds by brute force for the default shape; nothing in this repository is
itself machine-checked.

## 10. Distributed execution (v2)

Sections 1 to 9 describe the in-process protocol (`threshold-mldsa`, `cascade-tower`), which is
kept as the simulation harness and as the reference for the round structure. v2 adds a second
execution path in which every party is its own OS process (`cairn-net`, `mpc-bridge`).

### 10.1 Nodes and transport

| Node | Identity | Holds | Process |
|---|---|---|---|
| Signer | `leaf_i/signer_j` | one nested Shamir share (`.share` file) | `cairn node --role signer` |
| Root engine | `root_k` | per session: an additive share of the key | `cairn node --role root` |
| MPC party | slot 1..3 | whatever the MPC protocol gives it | backend process, reached over a Unix socket |
| Coordinator | `coordinator` | nothing secret | `cairn serve-kms --peers ...` |

Transport (`cairn-net::transport`): an exchange is one request frame and one reply frame on a
connection that is kept open and reused for later exchanges with the same node (a pool per
node; a dead pooled connection is retried once on a fresh one). A frame is a big-endian `u32` length and a `bincode`-encoded
`Frame {version, from, to, session, body}`. Every exchange runs under `tokio::time::timeout`;
a missed deadline is a `Timeout` fault against that peer. `--link-delay-ms` sleeps before each
send to emulate WAN latency.

Links are TLS 1.3 with client certificates (`cairn-net::tls`). `cairn keygen` creates a cluster
CA and one certificate per node whose DNS name is the node id (`leaf-2-signer-3.cairn`,
`root-1.cairn`, `coordinator.cairn`). A caller completes the handshake only with the node it
addressed (server-name check against the CA). A server requires a client certificate from the
CA, maps it to a node id through a pinned fingerprint table, and drops any frame whose `from`
is a different node. So `SubShare` is accepted only from the signer that owns the path, and
`Deal`, `Collect`, `Mask`, `Finish` only from the coordinator, with the sender authenticated.

### 10.2 Share compression

For active set `S` (three leaves, three signers each) with root coefficients `Λ_i` and leaf
coefficients `λ_j^(i)`:

```
signer (i,j):   ŝ(i,j) = Λ_i · λ_j^(i) · share(i,j)            (KeyShare::flatten)
                ŝ(i,j) = a_1 + a_2 + a_3,  a_k uniform          (AdditiveShare::split)
                send a_k to root engine k                       (Body::SubShare, point to point)
engine k:       s_k = Σ_(i,j) a_k(i,j)                          (AdditiveShare::sum)
                Σ_k s_k = Σ_(i,j) ŝ(i,j) = s  (mod q)
```

This applies to `s1`, `s2` and the 32 field elements of `K` alike. The leaf's share of the key,
`s~(i) = Σ_j λ_j share(i,j)`, would be a sum over a leaf's signers; no node computes that sum.

**Share check.** Engine `k` publishes `V_k(i,j) = A·a1_k(i,j) + a2_k(i,j)`. Each is uniform; their
sum over `k` is fixed by public data: `Σ_k V_k(i,j) = Λ_i λ_j · T(i,j)` with `T(i,j)` the
signer's dealt verification share. The coordinator checks this per signer
(`flatten::sub_shares_consistent`) and derives each engine's verification share
`T_k = Σ_(i,j) V_k(i,j)`. The seed `K` has no such check: a wrong `K` sub-share either fails the
backend's byte-range test (unattributed) or yields a different but valid mask.

### 10.3 Session

```
coordinator                 signers (16)                root engines (4)            MPC backend
   │── Prepare{message} ──────▶│ ─────────────────────────▶│
   │◀──────── Ready ───────────│◀──────────────────────────│      round 1: commitment
   │   choose 3 leaves × 3 signers, 3 engines
   │── Deal{active, roots} ───▶│── SubShare ─────────────▶│      point to point
   │◀──────── Dealt ───────────│◀─────── Ack ─────────────│
   │── Collect{active} ───────────────────────────────────▶│
   │◀──────── ShareCheck{V} ───────────────────────────────│      per-signer check
   │── Install{slot, T_1..3} ─────────────────────────────▶│
   │── Mask{attempt} ─────────────────────────────────────▶│── MASK ──────▶│
   │◀──────── Challenge{c~} ───────────────────────────────│◀─ c~, y_k ────│  round 2: challenge
   │── Finish ────────────────────────────────────────────▶│── RESPONSE ──▶│
   │◀──────── Verdict ─────────────────────────────────────│◀─ verdict ────│  rounds 3, 4
   │   reject: attempt += 1, back to Mask.   accept: assemble, verify, Abort (erase)
```

The coordinator needs the three engines to agree on `c~` and on the verdict; a lone dissenter is
named (`Equivocation`). On accept the backend opens the hint and each engine's `z_k`; the
coordinator sums them, encodes the signature and verifies it with RustCrypto `ml-dsa`.

Signers do nothing per attempt: a rejection repeats only `Mask` and `Finish`. The four rounds of
§3 map onto this as: commitment = `Prepare`/`Ready`; challenge = `Mask`; masked response and
hint/carry = `Finish` (the linear response is computed by the engine and bound by handing it to
the MPC, which also does the carry and hint aggregation).

### 10.4 Faults over the network

| Fault | Detected | Named | Effect |
|---|---|---|---|
| Node down | connection refused | node | skipped at once |
| Node stalled | wall-clock deadline | node | skipped after one deadline, excluded |
| Refuses the message | `Refused` reply | node | skipped |
| Wrong sub-shares | share check | signer | excluded, session re-formed |
| Sub-share not delivered | `DealFailed` / `missing` | engine / signer | excluded, re-formed |
| Engine reports another `c~` or verdict | 2-of-3 comparison | engine | replaced by the spare |
| Engine's `(z_k, r_k)` inconsistent | backend check `A z_k − r_k = c T_k` | engine (by slot) | replaced by the spare |
| Engine used another mask share | backend check `‖r − w‖∞ ≤ β` | none | engines rotated out in turn |

Exclusions persist across signatures and are cleared every `reinstate_every` signatures. A
re-formed session keeps the attempt counter, so `kappa`, the mask, `c~` and `z` are unchanged
and the result is still the deterministic signature. Each session uses a fresh random session
id and a fresh sub-sharing.

### 10.5 MPC bridge

`mpc-bridge::ipc` defines the party protocol: one Unix socket per party, frames of a big-endian
`u32` length plus a tagged payload, little-endian field elements.

| Tag | Message | Meaning |
|---|---|---|
| `0x01` | `MASK` | party's share of `K`, with `mu`, `rho`, attempt → `0x81 MASK_OK` (`c~`, party's share of `y`) |
| `0x02` | `RESPONSE` | party's `z_k`, `r_k`, with `t0`, `T_1..3` → `0x82 REJECT` or `0x83 ACCEPT` (hint, `z_1..3`) |
| `0x03` | `CLOSE` | drop the session → `0x84 CLOSED` |
| `0x8F` | `FAULT` | code 1 blames a party, 2 is unattributed, 3 is a protocol error |

What the backend computes is exactly the non-linear functionality of §2, for three parties:
`K = Σ k_k`; `y = ExpandMask(H(K ‖ 0³² ‖ mu), 5·attempt)`; `w = A·y`;
`c~ = H(mu ‖ w1Encode(HighBits(w)))`; then the per-party check, the mask check, the four abort
conditions and `MakeHint`. It opens `c~`; on accept the hint and `z_1..3`; on reject one bit.

Two users of the bridge:

- A root engine node holds one party socket and one share (`PartyClient`).
- `IpcEngine` implements `AttemptEngine` for the in-process tower by re-sharing the sealed sums
  three ways and driving all three sockets. It exists so the v1 state machines can run against
  any backend that speaks the protocol.

Two backends:

- `cairn mpc-worker` / `cairn-mpc-worker`: the reference worker. One process, three sockets,
  computes in the clear, deterministic. **Not a secure computation.**
- `mpc/mp-spdz/`: an MP-SPDZ program and a per-party bridge for a three-party honest-majority
  protocol over the field `Z_q` (`replicated-field-party.x -P 8380417`, or
  `malicious-rep-field-party.x` at reduced security). `replicated-ring-party.x` computes over
  `Z_2^k` and does not fit arithmetic modulo `q`. Verified on one machine against the reference
  and in the live sidecar flow; see that directory's README for the exact status.

### 10.6 Trust during signing

| Party | Sees | Can it learn the key alone? |
|---|---|---|
| Coordinator | message, public check values, `c~`, verdicts, accepted `z` and hint | no |
| One signer | its own share | no |
| One root engine | one uniform sub-share per signer; its sum `s_k`; its mask share | no |
| Two root engines | two of three additive shares | not from the sharing; **yes** inside an honest-majority 3-party MPC, where any two parties hold everything |
| Three root engines | all three shares | yes |
| The reference worker process | everything | yes (it is not an MPC) |
| A network observer | ciphertext | no (TLS 1.3) |
| The dealer machine | every share, the CA key, every node key | yes, at key generation |

So v2 moves the session-time trust from "nine signers in the right places" to "the root MPC's
corruption threshold among the engines". The tower still governs the shares at rest, who must
cooperate to start a session, and who can block one.

### 10.7 The flat committee (three-round protocol)

A second execution path with no MPC backend and no root engines (`cairn-net::flat`,
`threshold-mldsa::mithril`). It implements the protocol of *Efficient Threshold ML-DSA*
(USENIX Security 2026) for one committee of `T`-of-`N`, `N <= 6`.

**Keys.** One short ML-DSA secret per subset of `N - T + 1` parties; the key is their sum, and
each party holds the secrets of the subsets it belongs to. Any `T` parties hold all of them
between them; any `T - 1` miss at least one. The public key is a standard ML-DSA-65 key.

**One execution**, for an active set of exactly `T` parties, with `K` parallel repetitions:

```
coordinator                                   parties
   | -- Presign ------------------------------> |  ahead of time, for any message:
   | <------------ PresignCommit{id, H(w..)} -- |  sample K masks in a hyperball, w = A r1 + r2
   |
   | -- M2{message, presign id, commitments} -> |  take those masks out of the pool, bind them to
   | <------------ M2Reveal{w_1..w_K} --------- |  this session; check own commitment is in the set
   | -- M3{the others' w} --------------------> |  check every w against its commitment;
   | <------------ M3Response{z1 or none, xK} - |  per repetition: c from the summed w,
   |                                            |  z = c s_part + r, answer if ||z|| <= r
   | combine: first repetition all answered; hint from public values; verify
```

Round 1 (`Presign`) is independent of the message and of who signs. The coordinator fetches the
next execution's commitments during round 3 of the current one and once at startup, so a
request costs two round trips per execution. Openings are never revealed before the message
is fixed.

The signature is `(c~, sum of z1, hint)` in the standard encoding. An execution yields one
about half the time; the coordinator then starts a new execution with a fresh session.

**What the coordinator sees** is public: commitments, `w` values, and responses that passed
each party's own rejection test. It holds no share. It can make an execution fail by relaying
inconsistently; it cannot obtain a second answer under the same mask, because a party erases a
session's masks when it answers round 3, and precomputed masks leave the pool at round 2.

**Faults.** A silent or refusing party is excluded and another takes its place while more than
`T` remain. A wrong response is detected (the summed response fails the signing equation) but
the protocol cannot say whose it was, so the coordinator rotates the active set.

**Differences from the tower path.** The mask is sampled, not `ExpandMask`, so signatures are
valid but not deterministic. Security rests on the paper's argument (dishonest majority, up to
`T - 1` corruptions), which this prototype has not been checked against in detail. Key
generation here is by a dealer; the paper also gives a distributed one.

## 11. What is not solved

1. **A malicious-secure MPC backend.** The MP-SPDZ program runs and matches the reference with
   the semi-honest `replicated-field-party.x` on one machine. Stock `malicious-rep-field-party.x`
   refuses a 23-bit field at 40-bit statistical security, so active security needs an
   extension-field check. The program also opens a few values beyond the functionality of §2
   (listed in `mpc/mp-spdz/README.md`); that list has had no review. Multi-host runs are untested.
2. **Leaf committees as root parties.** With separate root engines the session-time trust set
   is the engines (§10.6). Keeping the 9-of-16 bound while signing needs each leaf to jointly
   play its root party (an MPC emulating an MPC party, or root engines that are themselves
   threshold-controlled by a leaf). No such protocol is implemented, and its cost is unknown.
3. **Dealerless key generation and share refresh** across the tower.
4. **Key and certificate lifecycle.** Links are authenticated, but the CA and every node key
   are generated by the dealer and copied to the nodes. Nodes generating their own keys and
   sending signing requests, rotation and revocation are not implemented.
5. **Proof.** No security argument for the composed protocol.
6. **Side channels.** The arithmetic is not constant time.
7. **Hedged signing.** Only the deterministic variant (`rnd = 0³²`).
8. **Robustness of the root MPC.** A three-party honest-majority protocol aborts if a party
   deviates; cairn then replaces an engine with the spare, and has only one spare.
