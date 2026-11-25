# Glossary

Terms as this repository uses them, roughly in the order you meet them.

| Term | Meaning |
|---|---|
| **ML-DSA-65** | The NIST post-quantum signature standard (FIPS 204), security category 3. Formerly Dilithium3. Public key 1,952 bytes, signature 3,309 bytes. |
| **Threshold signing** | Several parties hold shares of one key and produce a signature together; no party ever holds the key. The verifier sees an ordinary signature. |
| **Checkpoint** | A finalized block that the validators attest to, taken every K blocks. cairn signs checkpoints, not every block. |
| **`.pqcc` certificate** | PQC Sidecar's file format: the checkpoint fields plus one ML-DSA-65 signature. Defined in pqc-sidecar's `FORMAT.md`. |
| **pqc-sidecar** | An existing daemon that watches a chain, checks finality and writes `.pqcc` certificates with a single key. cairn replaces that key with a committee, without changing the daemon. |
| **Committee** | A group of at most six parties with a threshold `t`-of-`n`. |
| **Tower** | Committees nested in tiers. The default is four leaf committees of four signers each under a root tier: 16 signers, "3-of-4 × 3-of-4". |
| **Leaf / signer** | A leaf is one bottom-tier committee. A signer is one member, a validator's signing node, named `leaf_i/signer_j`. It holds one key share. |
| **Root engine** | A node (`root_k`) that holds an additive share of the key for the length of one signing session and plays one party of the MPC. Four run; three are active. |
| **Coordinator** | The process that receives the signing request and drives the session (`cairn serve-kms`). It holds no secret. |
| **Share / Shamir sharing** | A piece of the key. With `t`-of-`n` Shamir sharing any `t` shares determine the key and fewer reveal nothing. cairn nests it: across leaves, then within each leaf. |
| **Lagrange coefficient** | The public multiplier that turns a Shamir share into an additive one for a given set of participants. |
| **Share compression** | cairn's step that turns nine signers' nested shares into a three-party additive sharing held by the root engines, without anyone assembling a leaf's share or the key. |
| **MPC** | Multi-party computation: a protocol that lets parties compute on secret inputs and learn only the output. |
| **MP-SPDZ** | The open-source MPC framework cairn uses for the secret part of signing. |
| **Semi-honest / malicious security** | Semi-honest MPC protects secrets if every party follows the protocol. Malicious (active) security also holds when parties deviate. cairn's verified backend is semi-honest. |
| **Honest majority** | The MPC assumes fewer than half the parties collude: with three parties, at most one. |
| **Reference worker** | `cairn mpc-worker`: a stand-in for the MPC that computes in the clear. For tests and transport benchmarks only. |
| **MPC bridge / IPC** | The Unix-socket protocol between a root engine and its MPC party process (`crates/mpc-bridge`). |
| **Attempt** | One try at producing a signature. ML-DSA rejects about four of every five tries for safety, so a signature takes about five attempts. |
| **Rejection (Fiat-Shamir with aborts)** | The rule that discards an attempt whose values could leak the key. A rejected attempt reveals one bit. |
| **`ExpandMask`** | The FIPS 204 function that derives the per-attempt secret mask from a seed with SHAKE256. cairn computes exactly this function inside the MPC, which is why its output is byte-identical to a normal signer's. |
| **`HighBits` / `LowBits` / hint** | ML-DSA's rounding functions and the correction bits the signature carries for them. All non-linear, so they run inside the MPC. |
| **`c~`, `z`, `h`** | The three parts of an ML-DSA signature: challenge seed, response vector, hint. |
| **`kappa`** | The attempt counter that feeds `ExpandMask`; it advances by 5 per rejected attempt. |
| **Forging bound / blocking bound** | The fewest signers whose shares give the key (9 of 16) and the fewest whose absence stops signing (4 of 16). |
| **Identifiable abort** | When a protocol run fails, the party responsible can be named and excluded. |
| **Flat committee / party** | One committee of up to six nodes (`party_k`) running the three-round protocol directly, with no tower, root engines or MPC backend. |
| **Three-round protocol** | The threshold ML-DSA protocol of *Efficient Threshold ML-DSA* (USENIX Security 2026, "Mithril"): commit to masks, reveal, respond. Signatures verify under FIPS 204 but are not the deterministic ones. |
| **Execution** | One run of the three rounds. It yields a signature about half the time, so a signature takes about two. |
| **Trusted dealer** | A single machine that generates the key and hands out shares. cairn v2 uses one. |
| **KMS-compatible endpoint** | cairn answers the two AWS KMS calls pqc-sidecar already knows how to make, which is how the stock daemon signs through cairn. |
| **RTT** | Round-trip time of a network link. |
