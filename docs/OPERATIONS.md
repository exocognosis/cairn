# Operating a committee

Procedures for the three-round committee path. Each one is exercised by a test or script named
beside it; where it is not, it says so. Read [BLOCKERS.md](BLOCKERS.md) first: this is how to
run the software carefully, not a claim that it is ready to hold a valuable key.

## What each machine holds

| Machine | Secret files | Losing it | Leaking it |
|---|---|---|---|
| Party | `party_<k>.share`, `identity.pk8`, `tls/party_<k>.key` | Recover the share from the others (below). | Share: the key is one step closer to an attacker; make a new key by DKG. Identity or TLS key: replace it. |
| Coordinator | `tls/coordinator.key`, SigV4 secret | Start the standby. | The holder can ask parties to sign, and they will sign only what their policy allows. Revoke the certificate, change the SigV4 secret. |

Public and safe to copy anywhere: `committee.bin`, `roster.json`, `peers.json`,
`tls/fingerprints.json`, `tls/*.pem`.

## Creating the key with no dealer

For a committee you rely on, no machine may ever hold the whole key. Each operator does steps
1 to 3 on their own machine; nothing secret leaves it. (`cairn keygen` is a trusted dealer and
says so when it runs: tests only. `cairn committee-init` does steps 1 to 3 for every party on
one machine, for local trials.) This sequence was run as written, one directory per machine.

1. **Identity and certificate.** Each party, and the machine that will coordinate:

   ```bash
   cairn identity --out identity.key
   ```

   ```bash
   cairn tls-rotate --tls tls --id party_2
   ```

   The first prints the party's public identity, the second its certificate fingerprint. The
   coordinator needs only the second, with `--id coordinator`.
2. **Exchange the public values** over a channel you trust, and agree on the party numbers.
   Everyone writes the same two files: `roster.json`,
   `{"threshold": 2, "identities": ["<party_1 public>", "<party_2 public>", "<party_3 public>"]}`,
   and `peers.json`, `{"party_1": "<addr:port>", "party_2": "...", "party_3": "..."}`.
3. **Pin every other machine's certificate** (once per other party and for the coordinator):

   ```bash
   cairn tls-pin --tls tls --id party_1 --fingerprint <party_1 fingerprint>
   ```

4. **Each party waits for key generation:**

   ```bash
   cairn dkg-party --id party_2 --bind <addr:port> --roster roster.json --identity identity.key --tls tls --out keys
   ```

5. **The coordinator drives one run:**

   ```bash
   cairn dkg --roster roster.json --peers peers.json --tls tls --public-key-out public_key.hex
   ```

   Every party writes `keys/committee.bin` and its own share and exits. Compare the printed
   `key_id` across operators before using the key, then back up as below.

## Backup

- **Back up cold, once:** each party's share, identity key and `committee.bin`, encrypted, to
  storage only that party's operator controls. A share never changes, so one backup is enough.
- **Never back up or snapshot a running party.** See the next section.
- **Policy state (`--state`)** records the last height signed. Restoring an old copy would let
  the party sign a height again. If the state file is lost, start the party with a new state
  file only after the other parties have signed a higher height than this one ever did, or
  accept that this party's "never twice at a height" rule restarts from zero while the
  others' still holds.
- **The use record (`<rule file>.used`)**, when the organization rule has a use window, lists
  the payloads this party has authorized and when. Do not delete or restore it: a running
  party stops authorizing if an entry goes missing, and an old copy on a restarted party
  reopens the windows the copy does not list. See docs/ORG_POLICY.md.
- A lost share with no backup: `cairn share-recover` on the new machine, `cairn share-help` on
  enough others (tested end to end on 3-of-4; see `recover` unit tests).

## Never clone a party

A party's unused masks live in memory. A clone or a restored memory snapshot can answer a
second time with a mask the original already used, and two answers under one mask reveal the
share. Masks are erased after 120 s (`--mask-ttl-s`), so the exposure is that window, but the
rule is absolute: no live migration, no VM snapshot restore, no container checkpoint. Stop the
process, move the files, start it elsewhere. The `CairnPartyRestarted` alert exists so that
every restart is looked at.

## TLS certificates

Node links trust certificates by fingerprint (`tls/fingerprints.json`); there is no
authority. Each machine has its own copy of the table and re-reads it when it changes, so
none of the steps below restarts anything except the node changing its own certificate.
Tested by `certificates_rotate_and_revoke_without_an_authority`.

**A node makes its own certificate** (also the way to set up TLS with no dealer: every
machine runs this, then everyone pins everyone):

```bash
cairn tls-rotate --tls <dir> --id party_2
```

It prints the new fingerprint and the one it replaces. Send the new fingerprint to the other
operators over a channel you trust, the same way identity keys were exchanged.

**Rotate:** (1) the node runs `tls-rotate`; (2) every peer runs
`cairn tls-pin --tls <dir> --id party_2 --fingerprint <new>`, after which both certificates are
accepted; (3) restart the node; (4) every peer runs
`cairn tls-unpin --tls <dir> --id party_2 --fingerprint <old>`.

**Revoke:** every peer runs `cairn tls-unpin --tls <dir> --id party_2` (all of that node's
certificates) or with `--fingerprint` (one). Open connections under that certificate stop
being served at the next request.

Each operator edits only their own table. A node that one peer has unpinned and another has
not is reachable from the second only; the coordinator's table is the one that decides who
is asked to sign.

## Standby coordinator

The coordinator holds no key material and no state the parties depend on, so a second one can
run at any time. Tested in `processes_generate_a_key_together_and_sign_with_it`: two
coordinators with different certificates sign alternately through the same parties, a
conflicting checkpoint from one is refused by the parties, and one carries on after the other
is gone.

1. On the standby machine: copy `committee.bin`, `peers.json` and `tls/fingerprints.json`, then
   `cairn tls-rotate --tls <dir> --id coordinator`.
2. Every party operator: `cairn tls-pin --tls <dir> --id coordinator --fingerprint <new>`.
3. Run `cairn serve-kms` on the standby with the same SigV4 credentials.
4. On the sidecar's machine, run the relay and point the sidecar's `aws_endpoint_url` at it:

   ```bash
   cairn kms-failover --listen 127.0.0.1:8200 --backends coordinator-a:8200,coordinator-b:8200
   ```

   Each connection goes to the first coordinator that accepts it, starting with the one that
   last worked. The relay carries bytes only: with HTTPS on the endpoint, give both
   coordinators the same `kms-cert` certificate. Tested with an unmodified pqc-sidecar by
   `scripts/failover-check.sh`, which kills each coordinator in turn.
5. The relay switches when a coordinator stops accepting connections. A coordinator that is
   running but cannot reach the parties is not detected: the `CairnSigningFailing` alert is
   what tells you, and stopping that coordinator is the fix.

Both may be up at once. The parties, not the coordinators, enforce one checkpoint per height.

## Monitoring

- Coordinator: `cairn serve-kms --metrics-listen <addr:port>`.
- Party: `cairn node --role party ... --metrics-listen <addr:port>`.
- Both serve `/metrics` (Prometheus text) and `/healthz`, unauthenticated: bind them to a
  private address.
- Alert rules: [`deploy/prometheus-alerts.yml`](../deploy/prometheus-alerts.yml), with unit
  tests beside it. `scripts/alerts-check.sh` runs promtool on both and then has a real
  Prometheus scrape a live local committee and evaluate every rule. Set the number in
  `CairnTooFewParties` to your threshold. Delivery through an Alertmanager is yours to set up
  and has not been tried here.

## Upgrading

- Release archives carry SHA-256 checksums; verify before installing.
- A node drops frames whose wire version is not its own, so a committee on mixed wire versions
  does not sign. The wire version is `NET_VERSION` in `crates/cairn-net/src/wire.rs`; compare it
  between the two tags before upgrading.
- **Wire version unchanged:** upgrade parties one at a time (stop, replace the binary, start,
  watch `cairn_party_responses_total` move), then the standby coordinator, then the active one.
  The committee keeps signing while a threshold of parties is up.
- **Wire version changed:** stop the coordinator, upgrade every party, upgrade and start the
  coordinator. Signing stops for the duration.
- There is no compatibility promise for share, committee or policy-state files between
  versions yet, and no migration tool. Keep the cold backup and the old binary until the
  upgraded committee has signed.
- **0.7.0 to 0.7.1 with a use window:** first uses moved from `<digest>.used` files in the
  approvals directory to one file beside the rule file. The old files are ignored, so a
  payload whose window had closed can be authorized once more until its approvals expire.
  Upgrade when no approved payload is in that state, or remove its approvals first.
- A release binary can be rebuilt from its tag and compared: docs/RELEASING.md.
- `scripts/upgrade-rehearsal.sh` rehearses both on one machine and one key: v0.3.0 to v0.4.0
  rolling (wire version 2 in both), then to the current build with a stop (wire version 3),
  on the files v0.3.0 wrote, with a verified certificate after every step.
- **v0.4.0 and earlier to anything later is a wire-version change**: parties now sign the
  commitment set they are shown and refuse to answer without the others' signatures.

## Latency

`cairn serve-kms --parallel-attempts <k>` (default 2) runs k executions of the protocol side
by side for each signature and returns the first that succeeds. About half of all executions
end without a signature, so this saves round trips at the cost of bytes and party CPU. Use 1
on links where bandwidth, not round-trip time, is the limit.

## Suspected share leak

There is no share refresh. Run `cairn dkg` for a new key, have the chain or the consumers of
the certificates accept the new public key, then destroy the old shares.
