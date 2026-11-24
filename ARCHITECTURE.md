# Architecture

This document specifies the cairn v1 signing protocol: keys, the MPC boundary, the per-attempt
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

## 10. What v1 does not solve

1. **A real engine.** Replace `TrustedEngine` with an MPC among the root parties. The interface
   matches the existing MP-SPDZ program, which samples its mask inside the MPC; the exact
   `ExpandMask` variant in MPC is the part measured to hit the wall at N = 6.
2. **Virtual root parties.** A root-MPC party is a leaf committee. Each leaf must jointly play
   that party (an MPC emulating an MPC party, or a protocol-specific conversion of the leaf's
   Shamir sharing into root-MPC inputs). v1 models the hand-off with `Sealed` values; no such
   protocol is implemented, and its cost is unknown.
3. **Dealerless key generation and share refresh** across the tower.
4. **Transport.** mTLS framing, real timers, and authenticated senders (the `sender` field is
   trusted in the in-memory channel).
5. **Proof.** No security argument for the composed protocol; the `(z_p, r_p)` and mask checks
   are engineering measures whose interaction with a malicious-secure engine is unanalysed.
6. **Side channels.** The arithmetic is not constant time.
7. **Hedged signing.** Only the deterministic variant (`rnd = 0³²`) is implemented.
