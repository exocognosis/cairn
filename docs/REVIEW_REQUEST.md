# Request for review

cairn has had no review by anyone but its author, and there is no money for an audit. This
page is for a cryptographer or security engineer with a few hours: it says what to look at,
in order of what a mistake would cost, and what has already been checked so you need not
repeat it.

Any one question below is useful on its own. A "this looks right, I checked X and not Y" is
as welcome as a finding.

## What it is

An implementation of the three-round threshold ML-DSA-65 protocol of *Efficient Threshold
ML-DSA* (USENIX Security 2026) for a committee of 2 to 6 parties, with distributed key
generation, as separate processes over mutual TLS. Its signatures verify with unmodified
FIPS 204 verifiers. Rust, about 3,000 lines for the protocol, key generation and its
networking. The repository also holds an older two-tier design ("tower"); it is research and
not part of this request.

## The questions

Ordered by what an error would cost. Times are a guess for a reader who knows the paper.

**1. Does the response round leak the share? (2 to 3 hours)**
`crates/threshold-mldsa/src/mithril.rs`, `round3` and what it calls. The rejection test
decides whether `z = c s + r` is published. Is the test the paper's, is anything derived from
a rejected `z` observable, and is a mask ever used twice? Mask reuse across a crash or a
restored machine is discussed in docs/SECURITY_ARGUMENT.md; is that argument sound?

**2. Is the mask sampler close enough to the ideal distribution? (2 to 4 hours)**
`crates/threshold-mldsa/src/dd.rs` and docs/SAMPLER.md. Masks are sampled in double-double
arithmetic (about 106 bits). The document estimates a statistical distance of about 2^-73 per
mask by a counting argument with a stated assumption. Is the estimate right, and does the
paper's proof tolerate it at the number of signatures a key will make?

**3. Is the distributed key generation the paper's, and is its transport sound? (2 to 3 hours)**
`crates/cairn-net/src/dkg.rs`. Seeds travel sealed end to end between parties' identity keys,
through a coordinator that should see only ciphertext. Can a coordinator or one party bias
the key, learn a seed it should not, or make two parties finish with different keys?

**4. Do cairn's additions to the paper's protocol weaken it? (2 hours)**
docs/SECURITY_ARGUMENT.md states a claim, an argument and its limits for each: the relaying
coordinator, masks sampled ahead of time, two executions side by side, exclusion of a party
that answers wrongly, and each party's own signing policy. It ends with the gaps the author
knows. It is an argument, not a proof.

**5. Side channels (1 to 2 hours)**
docs/SAMPLER.md, section "Timing". Source-level branch-freedom, a check of the compiled
sampler (`scripts/ct-check.sh`, arm64 only), and a timing measurement
(`scripts/timing-check.sh`) that found one leak on an Apple M3 and reduced it with the
processor's data-independent-timing bit. A smaller difference remains for an all-zero share
only, located in the share multiplication, cause unknown. x86-64 has not been measured. Is the method
adequate, and what is the most likely leak it would miss?

## Already checked

- Compared line by line with the paper authors' public reference implementation: parameter
  sets, sampler, rounding, rejection test, sharing tables, challenge derivation, combine
  checks. One difference was found and aligned. The two implementations also sign together
  in mixed committees (`scripts/reference-interop.sh`). Details: docs/BLOCKERS.md, item 1.
- Signatures verify with RustCrypto's ML-DSA and with the unmodified pqc-sidecar verifiers.
- The same at scale: 600 keys dealt by the reference, 1,206 attempts, identical bytes from
  both combine procedures, and the same answer rate from both implementations' parties.
- A statistical test of published responses (`scripts/leak-check.sh`): over 105,000
  responses with a share at the bound, `<z, c s>` averages zero within half a standard
  error. It would see a missing rejection step (11 standard errors) and a partial one only
  above about 42% of that. One committee size, first moment only.
- Coverage-guided fuzzing of every parser of bytes from the network or another party's file
  (`scripts/fuzz.sh`): 32 million inputs, no crash. Ten minutes per target is short.
- An automated review by five independent model reviewers, one per question above. It found
  three defects in key generation (an extra partial key accepted, the relay able to choose
  the shared randomness, steps accepted out of order) and four elsewhere; those are fixed
  with tests. What it found and was not fixed is docs/BLOCKERS.md item 18. It is not a
  person's review and shares blind spots with the tools that wrote the code.
- Secrets are erased on drop in the protocol code, with the exceptions in item 18.

## Known limits, not findings

docs/BLOCKERS.md is the full list. The main ones: no share refresh (a leaked share stays
valid until a new key is generated), cost that rises steeply with the threshold, releases
that are not signed, and a signing procedure that is not the FIPS 204 algorithm even though
its output verifies.

## Running it

```sh
cargo test --workspace
./scripts/run_local_committee.sh --committee 3-of-4
```

The compiler version is pinned in `rust-toolchain.toml`. Tests that need outside tools print
SKIPPED without them.

## Reporting

Anything that could expose a key: GitHub's private vulnerability reporting on this
repository, or <rick@dytallix.com>. Everything else: a public issue is fine. Say which
commit you read. You will be credited unless you ask not to be. There is no payment.
