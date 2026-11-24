# FAQ

**Is this ready to protect real funds or a mainnet?**
No. It is a research preview. The MPC backend is semi-honest, two root engines can learn the
key during signing, one dealer creates the key, and nothing has been externally reviewed.

**What exactly is "standard" about the signature?**
It is a FIPS 204 ML-DSA-65 signature in the standard encoding under a standard public key.
A verifier cannot tell it from one made by a single signer. In fact it is byte-identical to
the deterministic signature a single signer with the same key would produce, and the tests
check that.

**Why not just aggregate many ML-DSA signatures?**
ML-DSA has no native aggregation. Aggregating with a proof system (a SNARK or a lattice
argument) works but puts a new verifier into every client. cairn's goal is that verifiers
change nothing.

**Why not one big threshold protocol over all validators?**
The secret part of ML-DSA signing has to run inside a multi-party computation, and that
computation becomes impractical at about six parties (measured: 28 GB of traffic at four
parties, 55 GB at five, failure at six, in the predecessor project). The tower keeps the one
expensive computation at three parties and reaches more signers by nesting.

**How many validators does it support?**
The tested shape is 16 signers. The share arithmetic and the bounds generalise to other shapes
(a 36-signer tower is in the tests for the in-process path); the networked path is built and
tested for 16.

**What does the 9-of-16 bound mean, and does it hold?**
Nine signers, three in each of three leaves, are the fewest whose stored shares yield the key.
No eight signers can, as in a flat 9-of-16 scheme. The tower is stricter than flat in one way
(nine or more signers in the wrong places still cannot: twelve spread 4, 4, 2, 2 fail) and
weaker in another (four absent signers can block, where a flat scheme needs eight). That is for
shares at rest. During a signing session the key is shared among three root engines, and with
the current honest-majority MPC two of them colluding can learn it. Milestone M4 is about
closing that gap.

**How fast is it?**
With real MPC across two hosts 178 ms apart: about 21 s per checkpoint, about 3 s per attempt.
On one machine with a stand-in backend: about 0.12 s. With the MPC parties on three separate
hosts it will be slower, and that has not been measured. The target is checkpoint cadence
(every K blocks), not per-block signing.

**What happens when a validator is offline or malicious?**
Any three of the sixteen signers can be offline, and one of the four root engines. A stalled node costs one
network deadline and is then skipped. A node that sends wrong shares or wrong MPC inputs is
named and excluded, and the session restarts with a spare.

**Do I need MP-SPDZ to try it?**
No. `cargo test` and the scripts use a built-in stand-in for the MPC. MP-SPDZ is needed only to
run the real secret computation; `mpc/mp-spdz/README.md` has the steps.

**Does it need changes to pqc-sidecar or the verifier?**
No. cairn exposes the KMS interface pqc-sidecar already supports, and the certificates are the
existing `.pqcc` format.

**Which chains does it work with?**
Anything pqc-sidecar follows, since cairn only replaces the signer: CometBFT chains, EVM chains
and Stellar. Every live run so far used a CometBFT stand-in, not a real chain.

**What is the Lean 4 work and where is it?**
The combinatorial bounds for nested threshold committees come from a separate Lean 4 library
(`CertTowers`). It is private and not included here; cairn cites its theorems by name and
checks the bounds it uses against brute force for the default tower.

**Can I use or modify the code?**
Not yet in a legal sense: the repository carries no license. Choosing one is on the roadmap.

**How do I report a security problem?**
See [SECURITY.md](../SECURITY.md).
