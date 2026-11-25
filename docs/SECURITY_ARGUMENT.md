# Security argument for what cairn adds to the protocol

The three-round committee protocol comes from "Efficient Threshold ML-DSA" (USENIX Security
2026), which has its own proof. cairn's implementation of that protocol was compared with
the authors' code and signs together with it ([BLOCKERS.md](BLOCKERS.md) item 1). This
document is about everything cairn puts around it, which the paper's proof does not cover.

It is an argument written by the builder, not a proof and not a review. Each section states
a claim, why it should hold, what it rests on, and where the argument stops. The last
section lists the gaps in one place; a reviewer should start there.

## Setting

- **Parties** hold shares. Fewer than T of N are corrupt; a corrupt party does anything.
- **The coordinator** holds no key material. It is assumed corrupt for secrecy and
  unforgeability, honest only for availability.
- **The network** is the adversary's, except that it cannot break TLS 1.3 or the primitives
  below.
- **Goals.** (1) No signature under the committee key on a message that T - corrupt honest
  parties did not each authorise under their own policy. (2) No information about honest
  shares beyond what the paper's protocol reveals. (3) Faults are detected, and attributed
  where the claim says so. Availability is not a security goal: a corrupt coordinator or T
  unavailable parties can always stop signing.
- **Primitives assumed:** SHAKE256 and SHA3-256 as random oracles or collision-resistant
  hashes as needed; Ed25519 unforgeable; X25519 with HKDF-SHA256 and ChaCha20-Poly1305 as an
  authenticated key exchange and AEAD; TLS 1.3 as implemented by rustls; HMAC-SHA256 (SigV4).

## 1. Relay through the coordinator

**What differs from the paper.** The paper's parties exchange messages with each other.
cairn's parties talk only to the coordinator, which forwards commitments and openings.

**Claim.** A corrupt coordinator gains nothing that a network adversary in the paper's model
with the ability to drop messages would not have. In particular, all honest parties that
answer in a session saw the same message and the same set of commitments.

**Argument.**
- A party checks at round 2 that the commitment listed for itself is the one it made, and
  fixes the whole set before revealing anything. At round 3 it checks every opening against
  that fixed set and uses its own opening from its own memory, never from the coordinator
  (`PartyNode::respond`, `PartyKey::round3`). So for each honest party, every `w` that
  enters its challenge was committed before that party revealed its own.
- **Agreement on the set.** With its opening, a party returns a signature, made with its
  TLS key, over the session, a hash of the message and the full commitment set it was shown
  (`commitment_statement`). At round 3 the coordinator must present every other active
  party's signature, and a party answers only if each one verifies over the statement the
  party itself signed, under a certificate its own table pins for that party. An honest
  party signs only the set it was shown, so if an honest party answers, every honest active
  party was shown the same session, message and set. The session is in the statement, so a
  signature cannot be moved to another session. Tested by
  `a_party_refuses_when_another_was_shown_a_different_commitment_set`: a different set, a
  different message, a signature replayed from another session, a missing signature and a
  signature in the wrong party's slot are each refused.
- The coordinator learns the openings `w` and the responses `z`. Both are public values in
  the paper's protocol.
- The coordinator cannot make a party answer twice with one mask: a mask is removed from
  the party's pool when round 2 starts and its session state is removed when round 3 is
  answered or fails (section 2).

**Rests on.** Parties' pin tables naming the right certificates for each other (section 6),
and the TLS keys' signature scheme (ECDSA P-256 as generated) being unforgeable. The TLS key
signs these statements under a prefix that a TLS 1.3 handshake signature cannot start with.

**Where it stops.** This gives the agreement the paper's model takes from its channels; it
does not re-prove the paper's theorem in the relayed setting. A corrupt party can sign
anything, as it can say anything in the paper's model. Through v0.4.0 there was no such check
and the argument for this section was informal.

## 2. Masks made ahead of time

**What differs.** Round 1 (sample masks, commit) runs before any message is known. The
coordinator holds a pool of commitments per party and names one when it starts a signature.

**Claim.** Each mask answers at most one challenge, and making masks early gives the
coordinator no more than running round 1 early in the paper's protocol would.

**Argument.**
- Round 1 of the protocol does not depend on the message, so running it early changes
  timing, not content.
- Single use: a party takes the named mask out of its pool before it does anything else in
  round 2; an unknown or already used name is refused; the session is deleted when round 3
  is answered, refused, aborted, or 120 s old; unused masks are erased at 120 s
  (`PartyNode::respond`). All of this state is in memory only, so a crash loses masks
  rather than reusing them.
- The coordinator chooses which early commitment to use after seeing the message and after
  seeing other parties' commitments, but not after seeing any opening: an opening is
  released only for a mask already bound to a session with a fixed commitment set. This is
  the situation three-round commit-reveal protocols are designed for, and running many
  sessions at once is something a corrupt coordinator could always do.

**Rests on.** The paper's protocol being secure under concurrent sessions. If its proof is
for sequential sessions only, this section and section 3 inherit that limit.

**Where it stops.** A cloned or snapshot-restored party has the same masks twice. Nothing in
the software prevents the operator from doing that; see OPERATIONS.md.

## 3. Retries and attempts side by side

**What differs.** About half of all executions end without a signature. The coordinator
retries, and can run several executions for one message at once (`parallel_attempts`).

**Claim.** This releases nothing that sequential retries would not.

**Argument.** Every execution uses fresh masks and its own session. A party answers each on
its own merits. The outputs are several independent executions on one message, which the
coordinator could request one after another anyway. Executions abandoned when another
succeeds have at most revealed `w` values, as a rejected execution does.

**Where it stops.** Same dependency on concurrent security as section 2. Several valid
signatures on one message may exist; they are all ordinary ML-DSA signatures.

## 4. Naming a wrong response

**What differs.** The committee key keeps a public key for every subset secret
(`GroupKey::subset_keys`), produced by the DKG. The paper's protocol detects that a
signature failed, not who caused it.

**Claim.** If a fully answered repetition fails the signature equation, the check names at
least one party whose response is wrong, and never names a party whose response is right.

**Argument.** A party's response is a known linear function of its masks' openings (public
after round 2), the challenge (public) and the subset secrets assigned to it for this active
set. With the subset public keys, `A z - c t_part - w` can be evaluated for each party from
public values (`mithril::blame`); an honest response satisfies it up to the same rounding
terms the signature equation allows, a wrong `z` does not. An honest party is never named
because its response satisfies its own equation regardless of what others sent.

**Rests on.** The subset public keys being right. In the DKG every member of a subset
recomputes that subset's public key from the secret it holds and checks the leader's
commitment to it before signing the transcript; a recovered secret is checked against it too.

**Where it stops.** The subset public keys are extra public information about the subset
secrets: each is an MLWE-style sample under the same matrix. Publishing them is not in the
paper. We believe it is covered by the same assumption that hides the key in the public key,
applied once per subset, but that is a statement about parameters (many samples under one
matrix, short secrets) that should be checked, not assumed. A party that stalls or refuses
is named by the transport, not by this check. Faults in round 2 (an opening that does not
match its commitment) are detected by every honest party but attributed only by the
coordinator's word.

## 5. Each party decides what it signs

**What differs.** The paper signs whatever message the parties are given.

**Claim.** An honest party that runs with a policy state file contributes only to
well-formed checkpoints that name this committee key and an allowed chain, never to one
below the last height it contributed to, and never to two different checkpoints at that
height. Since any T parties include at least one honest party, and any two sets of T honest
or corrupt parties share at least 2T - N parties, the committee key signs two different
checkpoints at one height only if no honest party is common to both signing sets.

**Argument.** A party parses the message itself, refuses anything that is not a checkpoint
for its committee key and (if configured) its chains, refuses a height below its last, and
refuses a second, different checkpoint at its last height. It writes the decision to disk
before it reveals its opening, and refuses if the write fails (`Policy::authorize`). A
signature needs T responses, so any signature passed the policy of every honest party in the
active set. The rule is per party, so two coordinators, a replayed request or a restarted
coordinator change nothing.

**Where it stops.**
- The policy binds the message format, not the truth of its content. Whether the block hash
  is the chain's is the sidecar's job; a corrupt coordinator with T - 1 corrupt parties needs
  only one honest party to be fooled about which checkpoint is real at a new height.
- A party that loses or rolls back its state file forgets its last height.
- The state file is written, synced and renamed into place before the party answers, but
  the directory is not synced, so a power loss right after the rename may lose the update on
  some filesystems.
- Two signing sets need not share an honest party when 2T - N is not larger than the number
  of corrupt parties (2-of-3 with one corrupt party, for example). Then the height rule
  holds per honest party but not for the key.
- "Never below" is each party's own last height. Honest parties that were not in earlier
  quorums may have lower last heights.

## 6. Links between nodes

**Claim.** A node processes a frame only if it arrived over TLS 1.3 from the holder of a key
whose certificate that node's own table pins for the frame's stated sender, at that moment.

**Argument.** Both directions verify the peer's certificate by fingerprint against the local
table, and the handshake signature against the certificate's key (`tls::Pinned`). The server
maps the certificate to a node and drops frames claiming another sender or another wire
version, re-checking the pin on every request; the caller pins the server's certificate to
the node it addressed and re-checks before reusing a connection. The table is local to each
machine and changes only when its operator edits it.

**Where it stops.** Trust in the table is trust in how fingerprints were exchanged, which is
out of band. Certificates carry no expiry that is checked. A party has no connection to the
other parties: what it believes about them comes through the coordinator, authenticated only
where section 1 says so (their signatures over the commitment set). A node's TLS key now
also signs those statements, so stealing it lets the thief vouch for commitment sets in that
party's name as well as open connections; it still yields no share.

## 7. Key generation and share recovery over the relay

**Claim.** The coordinator and the network learn nothing about any subset secret from key
generation or recovery, and a party accepts a secret only if it matches the committee's
public values.

**Argument.** Seeds and secrets travel sealed (X25519 ephemeral keys, HKDF, ChaCha20-Poly1305)
between parties whose ephemeral keys are signed by Ed25519 identity keys listed in a roster
every party was given. The coordinator relays ciphertext. A recovered secret is checked for
shortness and against the per-subset public key before it is stored (`recover::Pending`).

**Where it stops.** The roster is exchanged out of band. The DKG follows the paper's
appendix; whether cairn's transport preserves the properties that appendix proves (in
particular against a party that aborts after seeing others' contributions) has not been
argued here. Recovery restores availability only; a leaked share stays valid.

## 8. The signing endpoint and failover

**Claim.** The endpoint and the failover relay cannot cause a signature the parties' policy
would refuse, and hold nothing whose theft yields one.

**Argument.** Both sit in front of the coordinator, which is already assumed corrupt in
sections 1 to 5. SigV4 credentials, the endpoint's TLS key and the relay only limit who may
ask. The signature cache returns signatures already made for the same request. The
coordinator verifies every signature with a standard FIPS 204 verifier before returning it,
so a caller never receives an invalid one.

**Where it stops.** Nothing here; this section is the reason the earlier ones assume a
corrupt coordinator.

## Gaps, in order of importance

1. **The relayed setting as a whole (section 1).** Parties now agree on the commitment set
   by signature, which removes the equivocation question, but nobody has re-derived the
   paper's theorem for a relay with this check in place.
2. **Concurrent sessions (sections 2, 3).** The argument needs the paper's protocol to be
   secure when sessions overlap. Not verified against the paper's theorem statement.
3. **Publishing per-subset public keys (section 4).** Believed covered by the key-hiding
   assumption; parameters not checked for the number of samples published.
4. **Mask distribution and timing.** See [SAMPLER.md](SAMPLER.md): estimated 2^-73
   statistical distance per mask, no proof; timing checked for two functions on one
   architecture.
5. **DKG over the relay (section 7).** Abort behaviour not argued.
6. **Policy (section 5).** The one-checkpoint-per-height property of the key needs an
   honest party in the intersection of any two signing sets, which small committees do not
   guarantee; the state file's directory is not synced.
7. **Out-of-band exchange** of identity keys and certificate fingerprints is assumed done
   correctly.
