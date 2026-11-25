# From research preview to a production BLS-aggregation replacement

A gap analysis and a recommended path, written 2026-11-24. It supplements
[ROADMAP.md](../ROADMAP.md): the roadmap lists milestones for the current design, this document
asks whether the current design is the right one to finish.

Statements about other projects come from their abstracts, a conference slide deck and search
summaries, not from a full reading of the papers. Each is marked with its source, and nothing
here has been reproduced by us.

## The gap

| Dimension | BLS aggregation today | cairn today | What production needs |
|---|---|---|---|
| Latency | Milliseconds, non-interactive | 21 s per checkpoint (two hosts, MP-SPDZ on one of them); projected minutes with MPC parties on three hosts | Consistently under 2 to 3 s |
| Security of the signing computation | No joint computation | Semi-honest three-party MPC | Secure against deviating parties |
| Threshold while signing | Any subset's signatures aggregate | 9 of 16 at rest, 2 of 3 root engines during a session | The stated threshold at all times |
| Key generation | Each validator has its own key | One trusted dealer | Dealerless, with refresh |
| Number of signers | Thousands | 16 | At least the active checkpoint committee |
| Accountability | The aggregate names its signers | The signature does not show who signed | A decision: needed or not |
| Validator-set change | Keys are independent | Requires re-sharing | Re-sharing with a stable public key |
| Verifier | BLS library | Unmodified FIPS 204 | Unmodified FIPS 204 (cairn already meets this) |
| Review | Years of scrutiny | None | External review |
| Integration | Native to consensus | Sidecar through a KMS interface | Sidecar first, consensus-native later |

Two of these rows are not engineering gaps but differences in kind. A threshold signature
replaces "many signatures, one aggregate" with "one key, one signature": it cannot say which
validators took part, and it ties the validator set to a shared key. A chain that needs
per-validator accountability for slashing must keep that elsewhere.

## What changed in the field

cairn's design assumed that the secret part of ML-DSA signing needs a generic MPC, and that
such an MPC stops being practical at about six parties. Work published in 2026 challenges the
first assumption.

| Scheme | Source | Parties | Rounds | Generic MPC | Notes |
|---|---|---|---|---|---|
| Mithril ("Efficient Threshold ML-DSA", Celi, del Pino, Espitau, Niot, Prest; USENIX Security 2026) | abstract, slides | up to 6 | 3 | no | Signatures verify under ML-DSA; distributed key generation; 20 kB to 1 MB of communication; dishonest majority per a NIST workshop summary. Slides report tens to hundreds of milliseconds on a WAN for ML-DSA-44 (preliminary). |
| Quorus (Bienstock et al.; ePrint 2025/1163) | abstract | "any number" | reported 16 to 29 broadcast rounds (second-hand) | yes | Honest majority; about 100 kB per party per rejection round. |
| Masked Lagrange / Shamir nonce DKG (Kao; arXiv 2601.20917) | abstract, partial text | arbitrary T of N, benchmarks to 32 of 45 | 2 to 5 | for one check only | Millisecond figures on one machine; keygen description inconsistent between sections; not peer reviewed as far as we could tell. |
| TALUS (Kao, Chang; arXiv 2603.22109) | abstract, partial text | N at least 2T-1 in the MPC variant | 1 to 2 online | limited | Per-key signing cap with mandatory rotation; a TEE variant; not peer reviewed as far as we could tell. |

Two things stand out.

**None of these computes the FIPS 204 `ExpandMask`.** They all let the parties sample the mask
jointly (hyperball or sums of uniform values) and prove the result is still a valid ML-DSA
signature. cairn's most expensive component, about 1,940 MPC rounds per attempt, exists only to
reproduce the deterministic mask bit for bit. A verifier cannot tell the difference.

**Mithril's limit is the same six parties as cairn's.** Its replicated sharing needs one short
secret per subset of parties, so it stops at about six. That is exactly the size of one cairn
committee.

## Recommended path

### Step 1. Make "verifier-compatible" the requirement, and exact `ExpandMask` an option

Keep the existing MP-SPDZ path as an "exact mode" for anyone who must run the literal FIPS 204
signing algorithm. Make the default goal a signature that any FIPS 204 verifier accepts.
Expected effect: removes the mask circuit from the fast path. Engineering, not research. This
relaxes a hard invariant of the project, so it is the first question below.

### Step 2. A Mithril-style protocol for the root, in place of the generic MPC

Implement the three-round protocol among the root parties on cairn's existing nodes, TLS
transport, coordinator and fault handling, as a second backend next to the MPC bridge.
Expected effect, if the published figures hold for ML-DSA-65: latency from about 21 s to well
under the 2 to 3 s target; security against deviating parties without an honest majority;
dealerless key generation for the root. Mostly engineering against a published design, with
two unknowns: ML-DSA-65 performance (the figures we saw are for ML-DSA-44) and the retry rate,
which grows with the threshold.

### Step 3. Leaves as root parties: the research question, restated

Mithril needs each party to hold *short* secrets. cairn's share compression produces uniform
shares modulo q, which are not short, so the two do not compose directly. The natural
construction is a tower of the same protocol: each leaf committee runs the three-round protocol
internally to produce its root party's contribution. Whether the rejection rates and the
security argument survive nesting is open. This is the same open problem as roadmap M4, now
with a concrete candidate instead of "an MPC emulating an MPC party". Open research.

### Step 4. Decide the product shape before scaling

A flat six-party committee from step 2 is already a usable product for a small operator set.
Beyond six there are three routes: the nested tower of step 3 (research); a large-committee
scheme such as Quorus (honest majority, generic MPC, needs evaluation); or several small
committees each with its own key and a certificate carrying a few standard signatures (simple,
but the certificate format and verifiers change). Pick one after step 2 is measured.

### In parallel, cheap

- Three-host measurement of the current MPC (roadmap M1), now mainly to document the exact mode.
- Batch several attempts into one MPC run and open only the first that passes. The attempt
  counter is deterministic, so later attempts are known in advance. Untested.

## Questions, with recommended answers

1. **Must the signer run the exact FIPS 204 `ExpandMask`, or is it enough that standard
   verifiers accept the signature?** Recommended: verifier compatibility is the requirement;
   keep exact mode as an option. Alternative: keep exact mode mandatory and invest in a
   constant-round circuit, accepting much higher cost.
2. **Does the chain need to know which validators signed?** Recommended: no for the first
   product; cairn certifies finality that the chain's own consensus already made accountable,
   which is how pqc-sidecar is used today. Alternative: add signed participation records
   next to the certificate.
3. **How many signers per checkpoint?** Recommended: one committee of up to six operators for
   the first deployable version, then the tower. Alternative: wait for the tower.
4. **Implement Mithril from the paper, or build on the authors' code?** Recommended: implement
   in Rust inside this repository and test against their implementation if its license allows;
   contact the authors early. Alternative: wrap their Go implementation behind the bridge.
5. **Is "zero verifier changes" still absolute?** Recommended: yes. It is the property that
   distinguishes this project.

## Update, same day: decision and first prototype

The owner approved the path above, including question 1: **verifier compatibility is the
requirement, and exact `ExpandMask` becomes an optional mode** (the existing tower and MP-SPDZ
path).

With the paper in hand (the full version, 37 pages, including the ML-DSA-65 parameter table),
step 2 has a first prototype: `crates/threshold-mldsa/src/mithril.rs`. It implements the
paper's trusted-dealer key generation, the three signing rounds with `K` parallel repetitions
and imbalanced hyperball rejection, and the public combine, at the published ML-DSA-65
parameters.

What was checked:

- Certificates signed by a 3-of-4 committee are accepted by unmodified `pqc-sidecar verify`,
  the `pqc-sidecar-verify` npm package and RustCrypto `ml-dsa`.
- Every signing subset of 2-of-3 and 3-of-4 produces valid signatures; a wrong opening is
  refused; fewer than `T` parties are missing at least one secret.

Measured in one process on an Apple M3 (`cairn mithril-bench --signatures 50`), all parties'
work included, with this repository's slow reference arithmetic:

| T-of-N | K | executions per signature (mean / max) | compute ms per signature (mean / p95) | kB per party per execution |
|---|---|---|---|---|
| 2-of-3 | 5 | 2.34 / 7 | 67 / 170 | 35 |
| 3-of-4 | 20 | 2.54 / 10 | 427 / 1,341 | 130 |
| 3-of-5 | 62 | 1.78 / 6 | 923 / 2,588 | 357 |
| 4-of-4 | 26 | 1.82 / 7 | 536 / 1,763 | 169 |
| 2-of-6 | 8 | 1.74 / 8 | 78 / 223 | 55 |

Reading it:

- An execution is three message rounds. At the 178 ms round trip of the two-host run, a 3-of-4
  signature would cost about `2.5 x 3 x 0.18 s`, roughly 1.4 s of network time, plus compute.
  That is a projection from these numbers; the protocol has not been run over the network yet.
  The comparable measured figure for the current design is 21 s.
- The paper targets a success probability of one half per execution, so about two executions
  on average. Ours is slightly worse for the small sets, which is consistent with the simpler
  share partition used here but has not been investigated.
- Cost rises steeply with the threshold: the paper's `K` for 4-of-6 is 804 and for 5-of-6 is
  1,200 (6 to 9 MB per party per execution). Small thresholds are the practical range.

What the prototype is not: a secure implementation. Floating-point sampling, a trusted dealer,
no distributed key generation, no network path, not constant time, and written from the paper
without comparison against the authors' code.

## Update: on the network

The three rounds now run between separate party processes over the existing mutual-TLS
transport, relayed by the coordinator (`cairn-net::flat`), and `cairn serve-kms --committee`
exposes a committee behind the KMS interface. A stock pqc-sidecar signs a live checkpoint
through a 3-of-4 committee of processes and the unmodified verifier accepts the certificate.

Measured with each party as its own OS process on one Apple M3, 100 certificates per row,
injected round-trip time on every link (`cairn committee-bench`):

| RTT | committee | latency ms (mean / p50 / p95 / max) | executions (mean) | kB per party per cert |
|---|---|---|---|---|
| localhost | 2-of-3 | 35 / 34 / 68 / 151 | 2.06 | 108 |
| localhost | 3-of-4 | 92 / 97 / 245 / 346 | 1.86 | 549 |
| localhost | 3-of-5 | 276 / 275 / 553 / 1,102 | 1.99 | 1,776 |
| 50 ms | 2-of-3 | 376 / 208 / 935 / 1,248 | 2.01 | 106 |
| 50 ms | 3-of-4 | 479 / 238 / 1,161 / 1,885 | 2.04 | 602 |
| 50 ms | 3-of-5 | 613 / 320 / 1,568 / 2,822 | 1.95 | 1,740 |

(Table refreshed after values were packed; see the next section for the run across real
hosts, which is slower than these rows suggest.) Not yet done: distributed key
generation; request authentication on the KMS endpoint; any review of the implementation
against the paper's security argument.

## Update: across two hosts

One run on 2026-11-25: `party_1` and the coordinator on an Apple M3 on a home connection in the
US, the other parties on a Hetzner `cpx42` in Helsinki, 185 ms round trip, mutual TLS inside
SSH port forwards (`scripts/split-host/committee.sh`). The active set was `party_1` plus two
remote parties.

| committee | certs | latency s (mean / p50 / p95 / max) | executions (mean) | kB per party per cert |
|---|---|---|---|---|
| 2-of-3, values unpacked | 50 | 1.63 / 1.29 / 3.89 / 5.70 | 2.48 | 256 |
| 3-of-4, values unpacked | 50 | 4.60 / 3.48 / 12.64 / 16.28 | 1.72 | 917 |
| 2-of-3 | 50 | 1.02 / 0.76 / 2.33 / 3.08 | 1.64 | 86 |
| 3-of-4 | 50 | 3.90 / 3.22 / 9.41 / 12.61 | 1.84 | 544 |
| 3-of-5 | 20 | 6.30 / 6.24 / 11.66 / 16.53 | 2.10 | 1,872 |

A stock pqc-sidecar on the Mac also signed a live checkpoint through the cross-host 3-of-4
committee in about 3 s; the unmodified verifier accepted it and rejected a tampered copy.

What this run showed:

- **The injected-delay benchmark was too optimistic.** It predicted about 0.5 s for 3-of-4;
  the real link gave 3.9 s. Injected delay charges round trips but not the time to move data,
  and this protocol moves a lot: about 0.3 MB per party per execution for 3-of-4.
- **On this link, moving the data is the cost.** A raw transfer between the two hosts took
  about 0.8 s for 100 kB and 1.6 s for 400 kB upstream (after connection setup), which is TCP
  slow start over a 185 ms path from a home uplink. Three round trips are only 0.55 s.
- **Packing helped but not enough.** Sending values at 23 bits instead of 32 and no longer
  sending a party its own openings cut traffic by 40 to 65% and time by 15 to 37%.
- **2-of-3 meets the 2 to 3 s target here; 3-of-4 does not, on this link.** A coordinator in a
  datacenter near the parties should do much better; that has not been measured.

The next reductions, in order of expected effect: sample the masks ahead of time so round 1
and its upload happen before a request arrives (the paper notes round 1 can run offline); send
each party only what it needs to recompute the challenge and check commitments more compactly;
keep connections warm between rounds. None is done.

Limits of this run: one run, 20 to 50 certificates per row, one home uplink, an SSH tunnel
under the TLS links, shared vCPUs, a chain stand-in.

## Update: masks sampled ahead of time

Round 1 no longer waits for a request. A party samples its masks and commits to them when
asked (`Presign`), independently of the message and of who signs; the coordinator fetches the
next execution's commitments while the current execution is in round 3, and once at startup.
A signing request therefore starts at round 2, where the party binds the precomputed masks to
the message and the session and removes them from its pool. Only round 1 moved: the paper
allows that, and revealing the openings before the message is fixed is not covered by its
argument.

Same local benchmark as before, each party its own process, 100 certificates per row:

| RTT | committee | before, mean ms | now, mean / p50 / p95 ms | executions (mean) |
|---|---|---|---|---|
| localhost | 2-of-3 | 35 | 28 / 16 / 73 | 1.85 |
| localhost | 3-of-4 | 92 | 98 / 94 / 189 | 2.08 |
| localhost | 3-of-5 | 276 | 249 / 137 / 556 | 1.83 |
| 50 ms | 2-of-3 | 376 | 265 / 138 / 674 | 1.99 |
| 50 ms | 3-of-4 | 479 | 350 / 330 / 828 | 2.10 |
| 50 ms | 3-of-5 | 613 | 532 / 495 / 1,233 | 2.12 |

About a quarter faster where round trips dominate, as expected from three round trips becoming
two. It has **not** been re-measured across real hosts. There, moving the openings dominated
(rounds 2 and 3), and this change does not reduce that, so the gain on such a link should be
smaller: roughly one round trip per execution.

What would reduce the data itself is still open: the openings are uniform field elements and
do not compress, and each party must see every other party's openings to check commitments.
The remaining levers are placement (a coordinator near the parties, direct connections instead
of one tunnel) and fewer repetitions per execution, which is a parameter question for the
paper's analysis, not an engineering one.

## Update: first hardening pass

Without funding for review, the work now follows [BLOCKERS.md](BLOCKERS.md), which lists every
known blocker and its status. Done in this pass: SigV4 verification on the KMS endpoint and a
loopback-only rule without credentials; a signing policy enforced by each party with
persisted protection against conflicting or older checkpoints; audit logs.

## Update: no dealer

`cairn dkg` implements the paper's distributed key generation for the committee path, relayed
through the coordinator with end-to-end encrypted seeds. A committee of separate processes
generates its key and signs with it in the tests, and `scripts/run_local_committee.sh` uses it
by default. Remaining trust in setup: exchanging identity public keys, and the TLS authority.

## Update: attribution, arithmetic, mask lifetimes, and a real chain

Wrong responses are now attributed from public values; modular reduction is branch-free; unused
masks expire. And for the first time the system signed real blocks: an unmodified pqc-sidecar
followed Cosmos Hub mainnet through a public RPC endpoint in light-client mode, and a 3-of-4
committee whose key was generated without a dealer signed heights 34,035,530 and 34,035,540,
with the KMS endpoint requiring signed requests and every party restricted to that chain.
[BLOCKERS.md](BLOCKERS.md) has the current status of every item.
