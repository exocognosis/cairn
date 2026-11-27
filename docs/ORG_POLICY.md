# Organization policy: sign what enough approvers approved

`cairn node --role party --policy org` makes a party sign any payload, of any format, once
enough named approvers have approved exactly that payload for exactly this committee. It is
the counterpart of the default checkpoint policy for deployments that are not a chain.

## How it works

1. Every party holds the same rule file: how many approvals are required and each approver's
   name and ML-DSA-65 public key.
2. An approver signs a statement binding three things: the committee's key, the SHA3-256
   digest of the payload, and an expiry time. The result is one small JSON file.
3. The approval file is copied into each party's approvals directory, by whatever channel
   the organization trusts. The coordinator is not involved and cannot forge one.
4. When asked to sign, a party hashes the payload, looks in its own directory for approvals
   of that digest, checks each signature and expiry, and signs only if enough different
   approvers are there. It writes the decision to its audit log first; if the log is
   configured and cannot be written, it refuses.

## Commands

```bash
cairn approver-keygen --name alice --out org/
```

Writes `org/alice.approver.key` (secret, mode 0600) and `org/alice.approver.pub`.

Rule file, the same on every party:

```json
{ "required": 2, "approvers": { "alice": "<alice.approver.pub contents>", "bob": "...", "carol": "..." } }
```

```bash
cairn node --role party --id party_1 ... --policy org --org-rule rule.json --approvals /var/cairn/approvals --audit-log /var/cairn/audit.log
```

```bash
cairn approve --name alice --key org/alice.approver.key --committee-key public_key.hex --payload release.bin --out /var/cairn/approvals --ttl-secs 3600
```

Clients then ask for the signature as before (the KMS endpoint signs any message up to
4,096 bytes). With too few approvals the request fails with, for example,
`1 of 2 required approvals`.

## What is checked

| An approval does not count if | Tested in |
|---|---|
| It has expired | `cairn-policy/src/org.rs` |
| It was made for another committee's key | same |
| It is one approver's file copied under another's name | same |
| Its expiry was changed after signing | same |
| Its signer is not in the rule file | same |
| It is for a different payload | same, and `cairn-sidecar/tests/org_policy.rs` (real processes) |

A rule file is refused at start if it requires zero or more approvals than there are
approvers, lists one key under two names, or uses a name with characters other than `a-z`,
`0-9`, `-`, `_`.

## Limits

- **A use window, not a signing count.** With `"use_window_secs": <n>` in the rule file, a
  party authorizes a payload for `n` seconds from the first time it does so and refuses it
  afterwards, even if the approvals have not expired. It is a window rather than a single
  use because one request can take several sessions. Without the setting, an approved
  payload can be signed until its approvals expire.
- **Where first uses are kept.** In one file, `<rule file>.used` unless `--use-record <file>`
  names another, one line per payload, readable by its owner only. It is not in the approvals
  directory, so whoever delivers approvals cannot touch it. A running party also remembers
  every entry and refuses to authorize under a window if the file has lost one, so deleting
  or editing the file does not reopen a window; it stops signing until the file is put back.
  What remains: someone who can write the file and restart the party can remove an entry
  unnoticed, and that person can already read the party's share. The file grows by one line
  per payload and is never trimmed.
- **Signatures already made.** A signature stays valid for ever; a window cannot recall it.
  The KMS endpoint answers a repeated request from its cache without asking the parties, but
  only for 120 s after the signature was made (`--kms-cache-s <n>`, 0 to turn the cache
  off). Keep that at or below the use window.
- **The payload is opaque.** There are no amount limits, roles, or rules about content. What
  an approver approves is a digest; they must look at the payload themselves.
- **Approver keys are files.** There is no hardware token or login. To remove an approver,
  edit the rule file on every party: each party reads the file again when it changes, and
  the removed approver's approvals stop counting at once. A rule file that is missing or
  not valid makes the party refuse everything until it is fixed.
- **Delivery is yours.** cairn does not move approval files to the parties.
- **Clocks.** Expiry uses each party's own clock.
- **Both engines.** Tower signers and root engines take `--policy org` too, and a test runs
  the rule on all twenty tower processes. When too few tower nodes are left because their
  policies refused, the signer reports the refusal in the nodes' own words, and no node is
  dropped for refusing.
