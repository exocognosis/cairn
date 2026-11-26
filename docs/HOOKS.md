# Any chain, any organization: hooks instead of adapters

cairn contains no code for a particular chain, directory service or approval system. The
parts that differ between deployments attach as programs or local services the operator
owns. Three plug points take one:

| Plug point | Flag | The operator's program does | cairn does |
|---|---|---|---|
| What a party signs | `--policy-command`, `--policy-url` on `cairn node --role party` | Decides yes or no for one request | Asks before revealing anything; refuses on no, error or timeout |
| Who is on the committee | `--members-command` on `keygen`, `committee-init` | Prints the roster as JSON | Validates it and sets the committee from it |
| Asking for a signature | `cairn sign`, or the KMS endpoint | Calls it with a payload or checkpoint fields | Runs the committee and returns the signature |

## A policy hook

Every request is put to the hook first, then to the party's built-in policy
(`--policy checkpoint`, the default, or `--policy org`). `--policy hook` makes the hook the
only check.

The request:

```json
{ "session": "<hex>", "party": 2, "signers": [1, 2],
  "payload_hex": "<hex>", "payload_sha3": "<hex>" }
```

**A program** (`--policy-command '/opt/cairn/finality-check --rpc http://127.0.0.1:8545'`)
gets the request on standard input. Exit status 0 allows. Any other status refuses, and the
first line it printed is the reason the coordinator sees. It is run directly, without a
shell.

**A local service** (`--policy-url http://127.0.0.1:8181/v1/data/cairn/allow`) gets
`POST {"input": <request>}` and allows with `{"result": true}` or
`{"result": {"allow": true}}`. A `result.reason` string is passed on as the refusal reason.
These are the request and answer shapes of Open Policy Agent's data API, so a Rego rule
named `allow` in package `cairn` can be the policy. Only loopback IP addresses are accepted,
because the call is plain HTTP.

`--policy-timeout-ms` (default 2000) bounds either. Anything but a clear yes in time is a
refusal.

### For a proof-of-stake chain

Keep the default policy and add a hook that checks finality on that chain:

```bash
cairn node --role party ... --chains eip155:1 --state state.json --policy-command '/opt/cairn/is-final'
```

The hook decodes the checkpoint from `payload_hex` (format in pqc-sidecar's `FORMAT.md`:
chain id, epoch, height, block hash, finality commitment) and asks its own node or light
client whether that block is final. The built-in rules then make sure the party never signs
two checkpoints for one height or goes backwards. "Height" is any counter that only grows:
a block number, a slot, a round.

### For an organization

Either add a hook to the approvals policy (`--policy org --policy-url ...`: approvals and a
limit check), or let a rule system decide alone (`--policy hook --policy-url ...`).

## A roster command

```bash
cairn keygen --out keys --members-command '/opt/cairn/current-validators'
```

The program prints:

```json
{ "threshold": 3, "members": [ {"id": "val-a"}, {"id": "val-b"}, {"id": "val-c"}, {"id": "val-d"} ] }
```

## Asking for a signature

```bash
cairn sign --peers peers.json --committee committee.bin --tls tls --chain eip155:1 --epoch 7 --height 9000000 --block-hash 0x<hex> --certificate-out checkpoint.pqcc
```

```bash
cairn sign --peers peers.json --committee committee.bin --tls tls --payload release.bin --signature-out release.sig
```

The first builds the checkpoint message for any CAIP-2 chain id and writes a `.pqcc`
certificate; the second signs any bytes. Both print the message and signature as JSON. A
long-running caller uses the KMS endpoint instead.

## What a hook means for security

- **A hook is as trusted as the party.** Whoever controls the program or the local service
  decides what that party signs. It runs on the party's machine for that reason, and each
  party should run its own, against its own node or data.
- **The coordinator still cannot choose.** It sees refusal reasons, not the hook.
- **A slow hook holds up that party's reply** for up to the timeout, and one of the party
  process's worker threads with it.
- **Tested with stand-ins.** The tests use shell scripts and a minimal HTTP server speaking
  OPA's shapes. No run against a real Open Policy Agent, node or light client has been done
  here.
- **Limits that hooks do not lift:** the three-round protocol serves two to six unweighted
  members, and a changed roster needs a new key (no resharing).
