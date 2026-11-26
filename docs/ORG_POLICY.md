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

- **No signing count.** An approved payload can be signed any number of times until the
  approval expires. Each run gives a valid signature of the same bytes, so this leaks
  nothing new, but the policy does not make an approval single-use.
- **The payload is opaque.** There are no amount limits, roles, or rules about content. What
  an approver approves is a digest; they must look at the payload themselves.
- **Approver keys are files.** There is no hardware token, login, or revocation list.
  Removing an approver means editing the rule file on every party and restarting it.
- **Delivery is yours.** cairn does not move approval files to the parties.
- **Clocks.** Expiry uses each party's own clock.
- **Flat protocol only.** The tower's network nodes accept a policy in code but the CLI
  starts them with the checkpoint format check.
