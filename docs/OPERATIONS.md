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

## Backup

- **Back up cold, once:** each party's share, identity key and `committee.bin`, encrypted, to
  storage only that party's operator controls. A share never changes, so one backup is enough.
- **Never back up or snapshot a running party.** See the next section.
- **Policy state (`--state`)** records the last height signed. Restoring an old copy would let
  the party sign a height again. If the state file is lost, start the party with a new state
  file only after the other parties have signed a higher height than this one ever did, or
  accept that this party's "never twice at a height" rule restarts from zero while the
  others' still holds.
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
4. Failover is the sidecar's endpoint URL: a DNS name or a TCP load balancer in front of both.
   This step is not automated or tested here.

Both may be up at once. The parties, not the coordinators, enforce one checkpoint per height.

## Monitoring

- Coordinator: `cairn serve-kms --metrics-listen <addr:port>`.
- Party: `cairn node --role party ... --metrics-listen <addr:port>`.
- Both serve `/metrics` (Prometheus text) and `/healthz`, unauthenticated: bind them to a
  private address.
- Alert rules: [`deploy/prometheus-alerts.yml`](../deploy/prometheus-alerts.yml). The rules
  are written against the metric names in the code and have not been run in a Prometheus
  server.

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
- Rolling upgrades have not been rehearsed across two real releases.

## Suspected share leak

There is no share refresh. Run `cairn dkg` for a new key, have the chain or the consumers of
the certificates accept the new public key, then destroy the old shares.
