# Roadmap

Where cairn is, what comes next, and what each step needs and delivers. Written so that a
funder, a validator operator or a contributor can see what a unit of work buys.

## Where it stands (November 2026)

Done and tested: standard FIPS 204 output from a 16-signer tower; a real three-party MPC
(MP-SPDZ, semi-honest) doing the secret computation; separate processes over mutual TLS; a
two-host run at 178 ms; an unmodified pqc-sidecar signing live checkpoints through it.

Not done: active security for the MPC, the tower's bound holding during signing, dealerless
keys, outside review, a real chain. Those are the milestones below.

Effort figures are rough estimates for one experienced engineer and have not been validated
by doing the work.

## Milestones

### M1. MPC parties on three hosts

- **Why:** every MPC measurement so far had the three parties on one machine. The mask phase
  takes about 1,940 communication rounds per attempt, so across real links it is latency-bound.
  This number decides whether the current circuit is usable at checkpoint cadence.
- **Deliverable:** three root engines and their MP-SPDZ parties on three servers in different
  regions; a benchmark table for at least two region layouts.
- **Done when:** 100 certificates signed across three hosts with a stock pqc-sidecar, results in
  the README, and a go/no-go statement on round count.
- **Effort:** 1 to 2 weeks. **Depends on:** nothing.

### M2. Fewer rounds in the mask phase

- **Why:** if M1 shows tens of seconds per attempt, the round count must fall. Most rounds are
  the bit decompositions and the arithmetic SHAKE256.
- **Deliverable:** a restructured circuit (batched decompositions, constant-round comparison,
  or a mixed arithmetic/binary protocol for Keccak), still byte-exact against FIPS 204.
- **Done when:** the bridge tests pass unchanged and rounds per attempt drop at least fivefold.
- **Effort:** 4 to 8 weeks; research risk. **Depends on:** M1 for the target.

### M3. Malicious-secure root MPC

- **Why:** today a root engine that deviates from the MPC protocol is not prevented from
  learning secrets or forcing a bad output. This is the first thing a reviewer will ask about.
- **Deliverable:** the same circuit under an actively secure honest-majority protocol. Stock
  MP-SPDZ refuses the 23-bit field at standard security, so this needs an extension-field
  check, as the predecessor project's malicious ATLAS variant does.
- **Done when:** the bridge tests and the live sidecar flow pass on the active protocol at 40-bit
  statistical security or better, and an injected MPC deviation is caught.
- **Effort:** 6 to 10 weeks. **Depends on:** nothing; pairs well with M1.

### M4. The tower's bound during signing

- **Why:** shares at rest need 9 of 16 signers. During a session the key sits with three root
  engines, and two colluding ones suffice. Closing this is the scientific core of the project.
- **Deliverable:** a protocol in which each leaf committee jointly controls its root party (an
  MPC emulating an MPC party, or threshold-controlled root engines), with a written argument.
- **Done when:** a specification, a prototype for one leaf, and a cost measurement exist.
- **Effort:** 3 to 6 months; open research. **Depends on:** M3.

### M5. Dealerless key generation and share refresh

- **Why:** `cairn keygen` puts the whole key, the CA and every node key on one machine.
- **Deliverable:** key generation inside the MPC (the predecessor has this phase), sharing down
  the tower without a dealer, nodes generating their own TLS keys, and proactive refresh.
- **Done when:** a cluster is set up with no single machine ever holding the key, and a refresh
  changes every share while the public key stays the same.
- **Effort:** 6 to 10 weeks. **Depends on:** M3.

### M6. Security argument and external review

- **Why:** nothing here has been examined by anyone outside the project.
- **Deliverable:** a written security argument for the composed protocol, including the list of
  values the MPC program opens; then a paid review by a cryptography audit firm or an academic
  group, with findings published.
- **Done when:** the review report and the responses to it are public.
- **Effort:** 4 to 6 weeks of writing plus the reviewers' time and fee. **Depends on:** M3; best
  after M4.

### M7. Testnet pilot

- **Why:** every live run so far used a chain stand-in.
- **Deliverable:** cairn signing real checkpoints on a CometBFT testnet with independent
  operators running signers and root engines, and a light client verifying them.
- **Done when:** a week of unattended operation with published uptime, latency and fault logs.
- **Effort:** 4 to 8 weeks plus operator coordination. **Depends on:** M1, M3.

## Smaller items

- Hedged signing (random `rnd`) in addition to the deterministic variant.
- Constant-time arithmetic in the Rust FIPS 204 code.
- Certificate rotation and revocation for node TLS.
- Reusing engine shares across checkpoints to cut WAN setup time (see DECISIONS.md D-41, D-65).

## What support would go to

| Support | Unlocks |
|---|---|
| Three small servers for a month | M1 |
| One engineer for a quarter | M1, M3, and M5 or M2 |
| A research collaboration (MPC or lattice cryptography group) | M2, M4 |
| An audit budget | M6 |
| Validator operators willing to run nodes | M7 |

To discuss any of these, open an issue on the repository.
