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
