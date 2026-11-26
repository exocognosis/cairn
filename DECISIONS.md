# Decisions

Every engineering choice made autonomously while building cairn v1, with the reason. The brief
asked for no clarifying questions; where it was ambiguous or asked for something that cannot be
built honestly in one pass, the choice and its cost are recorded here.

## Scope and honesty

**D-01. The non-linear computation is an interface with an ideal-functionality stand-in.**
The brief asks for a threshold protocol with exact `ExpandMask`. That needs SHAKE256, rounding
and comparisons evaluated on secret shares, which is the multi-gigabyte MPC the predecessor ran
in MP-SPDZ. Writing a malicious-secure MPC in Rust was not feasible here, and a hand-rolled one
would be worse than none. v1 therefore defines the boundary precisely (`AttemptEngine`, two
phases, fixed openings, `Sealed` inputs) and ships `TrustedEngine`, which computes in the clear.
Everything outside the boundary is real. The README says plainly that this is not threshold
custody.

**D-02. Linear work is pulled out of the engine.** Signers compute `z_p` and `r_p` locally and
open `z_p` themselves. This is real share arithmetic, shrinks what an MPC must do, and gives the
engine a per-signer check (`A·z_p − r_p = c·w_p·T_p`) for attribution. Cost: mask-share
deviation is detectable but not attributable (D-12).

**D-03. Root parties are leaf committees, modelled, not realized.** Only the root tier runs the
engine, among at most six parties; each party is a leaf committee. How a leaf jointly plays an
MPC party is unsolved (ARCHITECTURE.md §11.2). The alternative, one delegate per leaf holding
the leaf's share, was rejected: three corrupt delegates would hold the key, collapsing the
tower's bound from 9 to 3.

**D-04. Trusted dealer.** Keys come from `KeyGen_internal` on a seed, then nested Shamir. This
makes the public key and signatures comparable byte-for-byte with a reference signer, which is
the strongest available correctness test. Dealerless generation is future work.

**D-05. All signers in one process, in-memory channel, logical timeouts.** The protocol logic,
codec and fault handling are exercised; sockets are not. A timeout is a counted event that adds
the configured round timeout to a logical clock. pqc-sidecar-threshold's mTLS transport is the
natural thing to put underneath later.

## Cryptography

**D-06. Clean reimplementation of FIPS 204 internals instead of porting.** The prototype's
`fips_sign.rs` is 3,000+ lines entangled with research scaffolding. `fips204.rs` is about 500
lines written from the standard and validated against RustCrypto `ml-dsa`: identical public keys
and identical deterministic signatures. Plain `i64` modular arithmetic, not constant time.

**D-07. Deterministic signing only (`rnd = 0³²`).** It is a FIPS 204 variant, needs no joint
randomness, makes output byte-comparable with a reference, and makes repeating a `kappa` after a
fault safe (same mask, same challenge, same `z`). Hedged signing needs a commit-reveal for `rnd`
and is left out.

**D-08. `kappa` advances only on rejection.** Fault retries reuse `kappa`, so the signature
equals the single-signer one regardless of faults. Session ids still change (they include the
retry counter), so messages cannot be replayed across retries.

**D-09. Shamir over `Z_q` for everything, including `K`.** The 32 seed bytes are shared as
field elements; the engine reconstructs and range-checks them. One sharing scheme, one Lagrange
routine, and nesting is just composition of weights.

**D-10. `t0` is public.** As in the ML-DSA analysis and the predecessor. The engine computes
`c·t0` from public data.

**D-11. Per-signer verification shares `T_p = A·s1_p + s2_p` are published.** They are Shamir
shares of the public `t`, so they add nothing an adversary cannot derive, and they make
inconsistent responses attributable. Seed shares get a hash commitment instead.

**D-12. Unattributed faults are handled by rotation.** Attributing a mask-share deviation would
need a verification share of `s1_p` alone (`A·s1_p`, 6 equations in 5 unknowns), which reveals
`s1_p`. Instead the engine detects the inconsistency before any verdict and the coordinator
suspends one spare-covered candidate per retry.

**D-13. One verdict for all four abort conditions.** The engine does not report which bound
failed, so retries leak one bit per attempt.

## Protocol

**D-14. Four rounds, named as in the brief.** `Commitment` fixes the signing set (it is a
participation binding, not a commitment to `w`: opening per-signer `w_p` would reveal `c·s2`).
`Challenge` is an echo of `c~`. `MaskedResponse` is a hiding commitment to `z_p`.
`HintCarry` carries the verdict, the openings and the hint.

**D-15. Exactly `t` active members per committee, lowest index first.** Fewer messages and
fewer parties exposed to mid-attempt faults; the spare enters only after an exclusion.

**D-16. Silence at round 1 is absorbed, not aborted.** The committee simply forms its set from
the members that answered and stops waiting for the silent one for the rest of the session.

**D-17. Exclusions persist until `reinstate`.** The certifier reinstates every 16 signatures by
default. Persisting avoids paying a known-offline signer's timeout at every checkpoint.

**D-18. `Committee` is a `Party`.** One state machine serves both tiers and would serve a
deeper tower. v1 builds two tiers only (`Tower`), because that is what is tested.

**D-19. `N ≤ 6` is enforced in constructors** (`Gadget::new`, hence `Committee::new`,
`TowerParams::new`, `deal`), so an oversized committee cannot be built.

**D-20. `bincode` for the wire format.** Compact and deterministic for these types. Not a
stable cross-version format; the header carries a version byte.

## Tower

**D-21. Bounds are cited from Lean and evaluated, not re-proved.** The `CertTowers` sources are
in a private tree marked not for publication, so they are referenced by theorem name only and
not copied into this repository. The brief describes the Lean model as "cascade domination";
the theorems that bound corruption for composed committees are its threshold-tree results
(`minAuth_isLeast`, `minBlock_isLeast`, `rootProb_*`), so those parameterize the tower.

**D-22. One seat per validator, stake-weighted draw, snake placement.** The Lean quorum file
also models proportional seat apportionment; with 16 seats that gives most validators zero
seats and lets one validator sit in several seats of a leaf. Sampling distinct validators keeps
"signers" and "validators" the same thing for the bounds. Requires at least 16 staked
validators.

## Sidecar integration

**D-23. No dependency on pqc-sidecar's code.** It is a binary crate under a different license.
The `.pqcc` v2 encoding is implemented from `FORMAT.md` and checked against the real verifiers
in the end-to-end test.

**D-24. KMS-compatible endpoint as the adapter.** pqc-sidecar already supports an external
signer through its `aws_kms` backend with an endpoint override. Speaking that protocol
integrates the tower with zero changes to the sidecar. The endpoint ignores request signatures
and must be bound to a private interface.

**D-25. "pqc-sidecar-verify" is taken to mean both verifiers.** The test runs the sidecar's own
`verify` subcommand (built from the local checkout, unmodified, at commit `c861717`) and the
published npm package `@exocognosis/pqc-sidecar-verify` 0.2.0, plus RustCrypto `ml-dsa`.
External verifiers are located through `scripts/setup-verifiers.sh`; when absent the test prints
`SKIPPED` unless `CAIRN_REQUIRE_EXTERNAL_VERIFIERS=1`.

**D-26. Certificates only at checkpoint heights.** `TowerCertifier::certify` refuses other
heights. On the KMS path the sidecar's `checkpoint.interval` sets the cadence.

**D-27. CLI harness instead of Criterion.** One run reports latency, the rejection histogram
and byte counts together, and can write JSON. In-process numbers would make Criterion's
statistical machinery misleading about a system whose real cost is the MPC.

## Repository

**D-28. Name `cairn`, private, no license granted (superseded by D-66).** `exocognosis/cairn` was free. No license
file is added; the owner should choose one.

**D-29. Repository location.** Created at `~/Developer/cairn`, next to the projects it builds
on. Nothing was written to those checkouts: pqc-sidecar is built into cairn's `target/`.

# v2: distributed execution

The v2 brief asked for TCP networking, a live pqc-sidecar `Sign` run, leaf-to-root share
compression and an MP-SPDZ bridge, again without questions. Choices and their costs:

## Topology and trust

**D-30. Root engines are separate nodes, and that changes the trust model.** The brief asks for
the nine active signers to be compressed into a 3-party additive sharing held by three root MPC
engines "while preserving the 9 of 16 to forge / 4 of 16 to block bounds". The compression is
implemented exactly as specified, but the claim does not hold as stated and the documentation
says so: for the length of a session the key is shared among three engines, so session-time
secrecy is the root MPC's threshold (two colluding engines under an honest-majority protocol),
not 9 of 16. The tower bounds still describe the long-term shares, who must cooperate to start a
session, and who can block. Preserving them during signing needs leaves to jointly play root
parties, which stays open (ARCHITECTURE.md §11.2).

**D-31. Four root engines, three active.** A three-party honest-majority MPC has no spare. A
fourth engine node lets the coordinator replace one faulty or offline engine; two bad engines
stop signing.

**D-32. 21 processes, not 16.** "16 OS processes" is the 16 signers. Root engines and the MPC
backend are separate processes too (4 + 1 with the reference worker), plus `serve-kms`.

**D-33. `serve-kms` is the coordinator.** The process that receives pqc-sidecar's `Sign` drives
the session. It holds no secret and never receives share material (checked on real frames in
`cairn-net/tests/cluster.rs`). It is trusted for liveness and for honest fault reports.

**D-34. Signers do no per-attempt work.** After compression the engines hold additive shares, so
they do the linear response step and only the two MPC phases repeat on rejection. This removes
nine signers from the rejection loop (their traffic no longer grows with attempts) and makes the
v1 commitment/opening rounds unnecessary on this path: the MPC binds the response by taking it
as input, and opens `z_k` itself on accept.

**D-35. The in-process protocol stays.** `threshold-mldsa` and `cascade-tower` keep their
state machines and all 32 v1 tests; they are the simulation harness and document the round
structure. The networked path is a second implementation in `cairn-net`, not a port, because a
synchronous call tree does not become a networked protocol by swapping a channel type.

## Transport

**D-36. One connection per exchange, request/reply.** Simple, no connection state to repair
after a fault, and a deadline per exchange maps one-to-one onto a fault against one peer. The
cost is a TCP handshake per exchange, which matters on a real WAN and is not modelled by the
injected latency.

**D-37. Plain TCP.** No TLS in v2: mutual authentication needs a PKI decision (node certificates,
rotation) that belongs with the deployment. The README, the transport module and DEPLOY_SPLIT.md
all say the links must be loopback or an encrypted tunnel. This is the largest practical gap.

**D-38. Deadlines are real.** `tokio::time::timeout` around every exchange; a stalled peer costs
the wall-clock round timeout once and is then excluded. Tests assert elapsed time.

**D-39. Address books are static files.** Each node reads `peers.json`; a signer sends
sub-shares only to engine addresses from its own file, never to addresses supplied by the
coordinator.

**D-40. Nodes sign checkpoint messages only.** Signers and engines refuse a message that does
not start with pqc-sidecar's `"pqc-sidecar/checkpoint/v2"` domain. A compressed sharing is
message-independent, so this is the engines' check that matters; it stops the KMS endpoint from
being a general signing oracle.

## Share compression

**D-41. Fresh sub-sharing per session.** Signers re-deal on every session and after every
re-formation. Caching the engines' shares across checkpoints would save one round and 0.3 MB,
at the price of long-lived key shares on the engines.

**D-42. Share check by linear images.** Engines publish `A·a1 + a2` per sub-share; sums are
checked against the signers' public verification shares. This names a signer that deals a wrong
share without revealing anything (each value is uniform, the sum is public). It cannot tell a
lying engine from a lying signer.

**D-43. No check on seed sub-shares.** A hash commitment cannot be checked through an additive
split. A wrong `K` sub-share makes the backend's range test fail (unattributed) or changes the
mask to another valid one; it cannot bias the mask without knowing `K`.

## MPC bridge

**D-44. The bridge protocol is the engine's two phases, per party.** `MASK` and `RESPONSE`
mirror `AttemptEngine::mask_phase` and `response_phase`, with each party sending its additive
share. The same frames serve the root engine nodes and `IpcEngine`.

**D-45. `IpcEngine` re-shares.** To sit behind the existing trait, which hands the engine
per-signer sealed inputs, the adapter does the public linear checks, sums, and re-shares three
ways (including fresh verification shares `T_k`). It adds no security; it lets the in-process
tower exercise the IPC path and any backend behind it.

**D-46. Reference worker: one process, three sockets, clear text.** The brief asks for a
deterministic external-process worker so `cargo test` covers the IPC round trip and rejection
loop without MP-SPDZ. It is exactly that and is labelled as not being an MPC everywhere it
appears. Its mask split is derived from the seed, so equal inputs give equal outputs.

**D-47. Replicated field, not replicated ring.** The brief names `replicated-ring-party.x`.
That protocol computes over `Z_2^k`; the shares and all arithmetic here are modulo
`q = 8380417`, so the MP-SPDZ target is `replicated-field-party.x -P 8380417` (or
`malicious-rep-field-party.x`).

**D-48. Unattributed faults rotate engines.** With one spare this resolves one bad engine.

## Sidecar integration

**D-49. `RAW`, not `EXTERNAL_MU`.** The brief mentions `EXTERNAL_MU`; the stock pqc-sidecar at
`c861717` signs with `MessageType = RAW`, so that is what the endpoint implements and what the
live test exercises.

**D-50. A CometBFT RPC stand-in for the live test.** pqc-sidecar needs a chain to follow.
`cairn mock-chain` answers the three JSON-RPC methods the `cometbft` adapter calls, with
`verify = "trust_node"`. It makes the live `Sign` test self-contained; it says nothing about
consensus verification, which is pqc-sidecar's and unchanged.

**D-51. `kms::serve` takes a `KmsSigner`.** The endpoint is generic over the in-process tower
and the TCP cluster; the cluster signer owns a small tokio runtime behind the blocking handler.

## Benchmarks and docs

**D-52. One-offline means stalled.** A dead process is refused immediately and costs nothing,
which would make the row uninformative. The benchmark uses a peer that accepts and never
answers, and reinstates it before every certificate, so the row shows the worst case.

**D-53. WAN latency is injected, not measured (superseded by the two-host run, D-60 to D-64).** `--link-delay-ms` sleeps before every send on
every node; nothing here ran across two hosts. DEPLOY_SPLIT.md gives the commands; they are the
same binaries and flags the local scripts run, and have not been executed on a split pair.

**D-54. The KMS endpoint answers retries from finished signatures.** pqc-sidecar's KMS client
abandons a `Sign` call after 5 s and retries. With MP-SPDZ a signature takes longer, so without
this every retry would start a new session and none would finish in time. The endpoint keeps the
last 256 signatures by message digest. Deterministic signing makes this exact: the cached bytes
are what a new session would produce.

**D-55. The MP-SPDZ program was written and run by a delegated agent, then re-checked.** Its
circuit, bridge and README are under `mpc/mp-spdz/`. Independently of its report, the
`mpc-bridge` tests and the live sidecar flow were re-run here against its bridges with
`replicated-field-party.x` and passed. Its per-phase timings are quoted from its README and were
not re-measured, apart from the phase times its bridge logged during those runs (consistent).

# v2.1: authenticated links

**D-56. Mutual TLS on every node link (supersedes D-37).** TLS 1.3, `rustls` with the `ring`
provider, client certificates required. Identity is a certificate from a per-cluster CA; the
caller pins the server by name, the server pins the client by certificate fingerprint and the
transport rejects a frame whose `from` differs from the authenticated node. This closes the
"`from` is a claim" hole and encrypts sub-shares in transit. Plain TCP is removed, not kept as
an option, so there is no insecure mode to select by accident.

**D-57. The dealer issues the certificates.** `cairn keygen` already creates every share on one
machine, so having it also create the CA and node keys adds no new trust; the CA key is
discarded after signing. Node-generated keys with signing requests belong with dealerless key
generation.

**D-58. Fingerprint table instead of parsing certificates.** The server identifies a client by
looking its certificate up in `fingerprints.json` rather than parsing the subject name out of
X.509, which keeps a parser out of the trust path. The cost is that adding a node means
redistributing the table.

**D-59. Still one connection per exchange.** Each exchange now also pays a TLS handshake. On
loopback that is CPU only; on a WAN it is an extra round trip that the injected-latency
benchmark does not model.

# v2.2: two-host run

**D-60. Pooled connections (supersedes D-36 and D-59).** The first two-host measurement was
16 s per certificate at 178 ms round trip, because every exchange paid a TCP and a TLS
handshake. The transport now keeps idle authenticated connections per peer and the server
serves any number of exchanges per connection. A connection returns to the pool only after a
complete exchange; a failed reuse is retried once on a new connection. Result: 6 s.

**D-61. A frame is one write.** Length prefix and body go out in a single buffer so a small
first write cannot wait behind Nagle's algorithm or a tunnel.

**D-62. SSH port forwards for the split run.** Only the Mac opens connections (coordinator to
nodes, leaf 1 signers to engines), so forwarding the server's node ports over SSH needs no open
port and no firewall change on the server, and both hosts can use the same loopback address
book. The cost is TCP-over-TCP under the TLS links; the numbers include it.

**D-63. `remote-bench` and `scripts/split-host/`.** The benchmark logic was split so it can
drive a cluster that is already running elsewhere; the two scripts are what the run used.

**D-64. A temporary server, deleted afterwards.** The only existing server hosts production
services with 2.7 GB free, so the run used a Hetzner `cpx42` in Helsinki for about 45 minutes
(billed one hour) and removed it together with the SSH key registered for it. `cx43`, `cx53`
had no capacity and `cpx41` is not sold in the EU sites.

**D-65. Setup cost left as is.** After pooling, most of a certificate's WAN time with the
reference backend is session setup payload (share-check values, opened `z`). Caching engine
shares across checkpoints or compressing those payloads would cut it; neither is done, because
with a real MPC backend the attempts dominate anyway.

# v2.3: public release

**D-66. Public, MIT.** On 2026-11-24 the owner made the repository public and chose the MIT
license, matching lattice-aggregation. Before publishing, the tree and history were scanned
for keys, tokens, addresses and local paths (none found), and links to the related projects
that are not public were reworded. MIT carries no patent grant; Apache-2.0 was the
alternative considered.

# v0.3 direction: verifier compatibility

**D-67. Exact `ExpandMask` becomes optional.** On 2026-11-24 the owner approved the path in
docs/PRODUCTION_PATH.md. The product requirement is now "any FIPS 204 verifier accepts the
signature"; reproducing the deterministic FIPS 204 signer bit for bit is an optional mode (the
tower with the MP-SPDZ backend). Reason: the exact mask costs about 1,940 MPC rounds per
attempt, and schemes published in 2026 avoid it entirely. Cost: signatures from the new path
are not those of a FIPS 204 signer, so "FIPS 204-compliant signing module" must not be
claimed for it; "verifies under FIPS 204" is the accurate statement.

**D-68. Prototype the three-round protocol from the paper.** `mithril.rs` follows "Efficient
Threshold ML-DSA" (USENIX Security 2026) at its ML-DSA-65 parameters. Written from the paper;
the authors' Go implementation was not located. Deviations: a greedy balanced share partition
instead of the max-flow optimum, `f64` hyperball sampling, trusted dealer only.

**D-69. Flat committee first.** The paper's scheme stops at about six parties and its cost
grows fast with the threshold, so the first deployable shape is one committee of up to six
operators with a small threshold. How leaf committees compose into a tower under this protocol
is open (docs/PRODUCTION_PATH.md, step 3).

**D-70. The three-round protocol runs through the coordinator (star topology).** Parties do not
connect to each other; the coordinator relays commitments and openings, all public. This reuses
the existing transport and keeps parties behind one inbound connection each. The cost is that
the coordinator can stall or spoil an execution, which it could already do.

**D-71. Masks are single-use, enforced at the party.** A party reveals once and answers once
per session, erasing the masks when it answers and discarding the session on any inconsistent
request. Reusing a mask under two challenges reveals the share, so this is enforced where the
secret lives, not at the coordinator.

**D-72. Wrong responses rotate the signing set.** The protocol gives no way to name the party
whose response was wrong. The coordinator distinguishes an honest failure (public bounds) from
a wrong response (the signing equation is off by a large amount) and rotates the active set in
the second case.

**D-73. `w` and `z1` travel packed at 23 bits (changed after the two-host run).** They were
first sent at four bytes per coefficient. The run across hosts showed data volume, not round
trips, dominating, so values are now packed and a party is no longer sent its own openings.

**D-74. A party takes its own openings from its own state.** The coordinator no longer relays
them, and a copy it sends anyway is ignored. This saves a third of round 3's traffic at T = 3
and removes a way for the coordinator to feed a party a different value for its own mask.

**D-75. Second two-host run, 2026-11-25.** Same method as D-62 and D-64: a temporary Hetzner
`cpx42` in Helsinki for about 40 minutes (one billed hour), deleted afterwards with its SSH
key. Results are in docs/PRODUCTION_PATH.md. The main finding is that the injected-delay
benchmark understates WAN cost for this protocol because it does not model data transfer.

**D-76. Round 1 runs ahead of time; rounds 2 and 3 do not.** Masks are sampled and committed
before any request and bound to a message at round 2. The paper notes round 1 is independent
of the message and signing set. Revealing openings before the message is fixed would save
another round trip but is outside the paper's argument, so it is not done. A party keeps at
most 16 unused mask sets and drops the oldest.

# Hardening without an audit

**D-77. The KMS endpoint verifies SigV4.** pqc-sidecar already signs every request with its AWS
credentials, so checking that signature authenticates callers with no change to the sidecar.
Verified against the real AWS client in the live test, including a wrong-secret refusal.

**D-78. No unauthenticated endpoint beyond loopback.** Without credentials `serve-kms` refuses
to bind a non-loopback address. A misconfiguration should fail closed, not expose signing.

**D-79. Policy is enforced by each party, not the coordinator.** Parties parse the checkpoint
and keep their own last-signed height on disk, written before they reveal. This is the
equivalent of a validator's double-sign protection. It supports checkpoint messages only;
general-purpose signing would need a policy language and is not attempted.

**D-80. Policy refusals do not exclude parties.** A refusal is correct behaviour, so the
coordinator reports it to the caller and leaves the committee as it was.

**D-81. Audit logs are plain JSON lines.** One per decision at each party, one per request at
the coordinator. No log shipping or tamper evidence; that belongs to the operator's tooling.

**D-82. Order of work without funding.** docs/BLOCKERS.md lists every known blocker with
status. Outside review and standards status cannot be bought with engineering; everything else
is taken in the order that removes the most risk per unit of work, starting with what an
operator would trip over first.

**D-83. Distributed key generation, relayed and end-to-end encrypted.** The paper's protocol
assumes secure point-to-point channels for the subset seeds. cairn's parties are connected
only through the coordinator, so seeds are encrypted to per-pair ephemeral X25519 keys that
each party signs with its Ed25519 identity. This keeps the star topology and removes the TLS
certificate authority from the set of things that could learn key material.

**D-84. Identities are separate from TLS certificates.** A party's Ed25519 identity signs its
key-exchange keys and the key-generation transcript; TLS only protects links. The identity is
generated by the party (`cairn identity`); the roster of public identities is the trust root
and must be exchanged out of band. `cairn committee-init` makes all of them on one machine and
is for local use.

**D-85. One-shot key-generation processes.** `cairn dkg-party` takes part in one key generation,
writes `committee.bin` and its share, and exits; the signing node is started afterwards. No
resharing or refresh yet.

**D-86. The paper's share partition tables.** `RSSRecover` now uses the balanced assignments
of the paper's Algorithm 6, relabelled for the active set, instead of a greedy balance. All
fifteen committee shapes are checked to cover every secret exactly once.

**D-87. Responses are publicly checkable.** With the per-subset public keys from key generation,
the half of a party's response that it does not send can be recomputed by anyone, and the
party's own acceptance test re-run with a small allowance for rounding. A wrong response fails
by a wide margin. This replaces rotation with attribution for keys that carry those values.

**D-88. Barrett reduction with masks.** `red` no longer divides or branches on its input.
This is a source-level property only; the remaining variable-time code (mask sampling with
`f64` functions, secret expansion) is listed in docs/BLOCKERS.md.

**D-89. Masks and open sessions expire.** 120 s by default at the party; the coordinator stops
using a prefetched commitment after 60 s. Cost: at checkpoint cadences slower than that, each
request pays round 1 again instead of using a prefetched one.

**D-90. A real chain through a public endpoint.** The first run against real blocks uses a
public Cosmos Hub RPC with pqc-sidecar's light-client verification, which checks validator
signatures itself, so the endpoint is not trusted for finality. The committee still runs on
one machine.

**D-91. Checked against the authors' code instead of waiting for them.** The paper's reference
implementation is public (https://github.com/Threshold-ML-DSA/Threshold-ML-DSA). Its `thmldsa65/internal` package was read
against `mithril.rs`: parameters, sampler, rounding, rejection test, sharing tables, challenge
and combine agree. The one difference (a hint-error norm exactly equal to gamma2) was aligned
to the reference. The reference was read, not executed or linked; the sharing tables are
restated as a test. Float sampling is kept because the reference does the same.

**D-92. Interop with the reference as an opt-in test.** `scripts/reference-interop.sh` clones
the reference at a pinned commit into `target/`, adds one test file
(`interop/reference/cairn_interop_test.go`) that exposes its own functions step by step, and
runs mixed Go/Rust committees. It is ignored by default and not in CI, because it needs Go
and a network fetch. The reference hashes `tr || msg`, so it is given `0 || 0 || msg` to
match FIPS 204's empty-context encoding. D-91's "read, not executed" no longer holds.

**D-93. TLS on the KMS hop by termination in front of the HTTP server.** `tiny_http`'s own TLS
needs an old rustls. Instead a small relay accepts TLS (rustls, the version already used
for node links) on the listen address and forwards to the HTTP server on loopback. Server
certificate only: callers are authenticated by SigV4. The certificate is self-signed and the
caller trusts that exact certificate; pqc-sidecar does so through `SSL_CERT_FILE`.

**D-94. Metrics on their own listener.** `/metrics` and `/healthz` are unauthenticated, so
they are served on a separate address that defaults to off, not on the signing port.

**D-95. Share recovery, not refresh.** A lost share is rebuilt from the other holders of each
subset secret and verified against the public per-subset keys. The exchange is file based
and the requesting process must stay alive, because the X25519 keys it decrypts with are
ephemeral and never written to disk. No refresh is offered: re-randomising short shares
without growing them is an open design problem, and offering something weaker under that
name would mislead operators.

**D-96. Pinned certificates, no authority.** Node links now trust a certificate because its
fingerprint is in the local table, for the node addressed (as server) or for some node (as
client). The cluster CA is gone. It added nothing the table did not already decide, its key
had to exist on one machine at setup, and with it destroyed no certificate could ever be
replaced. Certificates are self-signed; `cairn tls-rotate` makes one on the machine that will
use it. Tables written by earlier versions load unchanged.

**D-97. The table is followed on disk and checked per request.** A node re-reads
`fingerprints.json` when its modification time changes, the server checks the pin on every
request and the caller before reusing a pooled connection. Revocation therefore needs no
restart and no revocation list. A node may have several fingerprints, which is what makes
rotation overlap possible and what lets a standby coordinator have its own key.

**D-98. Coordinator redundancy by duplication.** The coordinator has no state the parties
rely on, so availability is a second coordinator, not a consensus protocol between
coordinators. Safety under two active coordinators rests on the parties' height rule, which
is tested. Switching the sidecar between them is left to DNS or a load balancer.

**D-99. Frames of another wire version are dropped.** Mixed versions fail closed instead of
misparsing.

**D-100. Failover is a byte relay beside the sidecar.** `cairn kms-failover` forwards each
connection to the first coordinator that accepts it. It terminates nothing and holds no key,
so it adds no party to trust, and beside the sidecar it fails only when the sidecar's machine
does. Health is "accepts a connection"; a coordinator that is up and unable to sign is left
to alerting, because deciding that from outside would mean parsing requests.

**D-101. Attempts side by side.** The coordinator may run several executions for one message
at once and keep the first signature (`parallel_attempts`, default 2 in `serve-kms`, 1 in the
library). A corrupt coordinator could always open concurrent sessions, so this exposes
nothing new; it costs bytes and party CPU. Measured with injected delay only.

**D-102. Double-double sampler with its own elementary functions.** The mask sampler and the
rejection test moved from `f64` and the system `ln`/`cos` to double-double arithmetic with
fixed-sequence `ln` and `cos` and no fused multiply-add. Reasons: the estimated distance
from the ideal distribution drops from about 2^-18 to about 2^-73 per mask, and the system
functions choose their path by the argument, which here decides a secret. Cost: a mask takes
about 2.5 ms of CPU; repetitions are computed on parallel threads. cairn no longer samples
exactly as the reference does, which interoperation does not need: each party samples its
own masks.

**D-103. A 256-bit reference in the tests.** `astro-float` is a dev-dependency used to run
the sampler's formula at 256 bits on the same uniforms. It is what makes hand-written
numerics acceptable here: every function and the whole pipeline are compared with it.

**D-104. Security argument as a document with a gap list.** `docs/SECURITY_ARGUMENT.md`
argues each addition separately and ends with what it does not establish. It is written to
be attacked: the gaps are listed in order so a reviewer starts with the weakest point.

**D-105. Parties sign the commitment set, with their TLS keys.** In round 2 a party returns
a signature over (session, hash of message, all commitments); in round 3 it answers only if
every other active party's signature over the same statement verifies under a certificate
its own table pins for that party. This gives through an untrusted relay the agreement the
paper takes from its channels. The TLS key was chosen over the DKG identity key because
every signing node already has it, every peer already pins it, and rotation and revocation
already work; the price is one key with two uses, separated by a prefix no TLS 1.3 handshake
signature can carry. The coordinator checks the signatures too, so that a party sending a bad
one is named instead of the honest parties that refuse because of it. Wire version 3.

**D-106. One kernel, three layers.** The signing engines know nothing about what is signed
or who asks. `cairn-core` holds the interface both engines share (`ThresholdSigner`,
rosters, verification); `cairn-policy` holds what a party will sign; `cairn-gateway` holds
client protocols. Chains and organizations differ in the last two only, so they are where
new code goes. `docs/ARCHITECTURE.md` has the boundaries.

**D-107. The policy is a trait the party owns.** `PolicyEngine::authorize_sign(&self, ctx,
payload)` takes `&self` so a party can consult it from any connection; an implementation
with memory locks inside. The checkpoint rules moved unchanged into
`cairn_policy::pos` and are wrapped as `PosCheckpointPolicy`; `cairn_net::policy` still
re-exports them. Refusal reasons travel as the same strings, so the wire format (version 3)
is untouched.

**D-108. `reshare` exists and refuses.** The signer interface has the method so key-lifecycle
callers have one entry point, and every backend returns `Unsupported`. An interface that
pretended otherwise would be worse than none.

**D-109. Weights stop at the roster.** A `Roster` carries weights because the tower's
assignment and any chain adapter need them. The flat protocol has none, so
`Roster::flat_shape` refuses weighted or oversized rosters instead of approximating them.

**D-110. The KMS front end keeps `cairn-net` as a dependency.** Its TLS listener is the one
in `cairn-net`. Moving that into a transport-free crate is possible and was left: it would
change no behaviour and the gateway already takes any `ThresholdSigner`.

**D-111. Tower nodes ask the policy trait too.** `SignerNode` and `RootNode` hold a
`PolicyEngine`; the default, `pos::CheckpointPrefix`, is the format check they had, with the
same refusal text. No node in `cairn-net` decides what is signable any more.

**D-112. Approvals arrive as files, not on the wire.** The organization policy reads
approvals from the party's own directory. Carrying them in the signing request would need a
new wire version and would route them through the coordinator, which is the component the
policy exists to distrust. The price is that delivery is the operator's job.

**D-113. Approvers sign with ML-DSA-65, under their own context string.** A classical
approver signature would be the weakest link of a post-quantum committee. The statement is
committee key id, payload digest and expiry; the FIPS 204 context `cairn/approval/v1`
separates it from every other signature in the system.

**D-114. No audit line, no signature.** With an audit log configured, the organization
policy refuses when the line cannot be written and synced. An unrecorded authorisation is
the failure an audit log exists to prevent.

**D-115. A roster sets the committee at key generation, by position.** `--members
<roster.json>` on `keygen` and `committee-init` takes T and N from the roster and makes party
`k` its `k`-th member; `members.json` records that, with each member's DKG identity key when
`committee-init` made one. The flag is not called `--roster` because the DKG commands already
use that name for their list of identity keys.
