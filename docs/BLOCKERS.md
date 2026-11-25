# What stands between this and production

An honest list, for the three-round committee path (the one fast enough to deploy). It is the
builder's own list, not an audit; a reviewer will add to it. Status as of 2026-11-25. Also done since the first version: the share partition now uses the paper's tables.

## Would leak or lose a key

| # | Blocker | Status |
|---|---|---|
| 1 | The protocol was written from the paper and never compared with the authors' implementation or reviewed by them. A subtle deviation in the rejection step can leak the key over many signatures without any test failing. | Open. Needs the authors or a reviewer. |
| 2 | Masks are sampled with `f64` arithmetic and a textbook Gaussian method; the security argument assumes an exact distribution. | Open. |
| 3 | Arithmetic and the rejection test are not constant time. | Partly. Modular reduction is now division-free and branch-free at the source level. Still variable time: the floating-point functions used to sample masks, and secret expansion during key generation. Nothing is verified at the machine-code level. |
| 4 | A trusted dealer created the key, every share, the TLS authority and every node's TLS key on one machine. | **Mostly done.** `cairn dkg` implements the paper's distributed key generation: no machine holds the whole key, and seeds travel end-to-end encrypted so the coordinator and TLS authority see only ciphertext. Still open: parties must exchange identity public keys out of band, TLS certificates still come from one authority, and the implementation is as unreviewed as the rest. |
| 5 | No share refresh, no replacing a party, no certificate rotation or revocation. | Open. |
| 6 | Mask state is memory only. A crash loses it safely, but nothing stops a cloned or snapshot-restored machine from answering twice with one mask, which reveals its share. | Partly. Unused masks and half-finished sessions are erased after 120 s, which bounds what a restored snapshot can replay to that window. The rule still stands: never clone or restore a running party. |

## Would stop an operator deploying it

| # | Blocker | Status |
|---|---|---|
| 7 | The KMS endpoint accepted requests from anyone who could reach it. | **Done.** Requests are verified against AWS SigV4 credentials, tested with the stock pqc-sidecar's own AWS client; without credentials the endpoint binds loopback only. No TLS on that hop yet. |
| 8 | Signing policy was a hard-coded prefix check, and parties trusted the coordinator's choice of message. | **Done for checkpoints.** Each party parses the checkpoint itself and refuses the wrong key, unlisted chains, a lower height, or a second checkpoint at a height, with the last height kept on disk. Other message types are not supported. |
| 9 | A wrong response is detected but cannot be attributed; a persistent bad party is found only by rotation. | **Done.** The committee key keeps the per-subset public keys, so anyone can check one party's response against public values; a wrong response is named and the party excluded. |
| 10 | The coordinator is a single point of failure for availability (not for secrecy). | Open. |
| 11 | Latency on real links: 3-of-4 took 3.9 s between a home connection and Helsinki, against a 2 to 3 s target. One link measured. | Partly. Masks are now precomputed; data volume remains. |
| 12 | Cost grows steeply with the threshold; practical committees are 2-of-3 to 3-of-5. | Inherent to the scheme's parameters. |
| 13 | No metrics, alerting, backup procedure, upgrade path or packaged release. | Partly. Parties and the coordinator now write audit logs. |
| 14 | Never run against a real chain; every live run used a CometBFT stand-in. | Partly. `scripts/real-chain-demo.sh`: an unmodified pqc-sidecar followed Cosmos Hub mainnet through a public RPC in light-client mode and a local 3-of-4 committee signed blocks 34,035,530 and 34,035,540. Not done: operators on separate hosts, long-running operation, a chain that consumes the certificates. |

## Only others can provide

| # | Blocker | Status |
|---|---|---|
| 15 | Independent security review. | Open. Not funded. |
| 16 | The signatures verify under FIPS 204, but the signing procedure is not the FIPS 204 algorithm and nothing is FIPS 140 validated. NIST's threshold process is still open. | Open, and outside this project's control. |
| 17 | A written security argument for cairn's own additions (coordinator relay, precomputed masks, fault handling, policy). | Open. |

## What can be done without funding, in order

1. Write to the paper's authors with the repository and specific questions (item 1).
2. ~~Distributed key generation from the paper's appendix (item 4).~~ Done; attribution from per-subset keys remains (item 9).
3. An exact sampler and the rest of constant-time (items 2, 3). Reduction is done; sampling is the open part and needs the authors' guidance on precision.
4. Share refresh and party replacement (item 5). The paper does not give a refresh for its short shares; this needs design work, not just code.
5. TLS on the KMS hop, metrics, packaged releases (items 7, 13).
6. Operators on separate hosts following a real chain for days (item 14).
