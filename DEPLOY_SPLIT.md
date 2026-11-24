# Split-host deployment

Run one cairn cluster across two machines:

| Host | Runs |
|---|---|
| **Mac** (Apple Silicon) | Leaf A: `leaf_1/signer_1..4`; `cairn serve-kms` (coordinator); `pqc-sidecar` |
| **Linux** server | Leaves B to D: `leaf_2..4/signer_1..4`; root engines `root_1..4`; the MPC backend; CometBFT |

**Status.** This split was run once, on 2026-11-24, between an Apple M3 and a Hetzner server in
Helsinki (178 ms apart), with the reference worker and with MP-SPDZ, including a stock
pqc-sidecar signing a checkpoint; results are in the README. That run used the two scripts in
`scripts/split-host/` with every node on loopback and SSH port forwards between the hosts
(section 6). The direct-address layout in sections 2 to 4 uses the same binaries and flags but
has not itself been run. `cairn mock-chain` stood in for CometBFT. Read the three notes first.

1. **Links are TLS, keep them private anyway.** Node links are mutually authenticated TLS 1.3,
   so sub-shares are encrypted in transit. Still bind nodes to private or tunnel addresses
   (WireGuard, Tailscale) and firewall the ports: the endpoints are unreviewed research code.
2. **The MPC backend decides what this deployment is.** With `cairn mpc-worker` (the reference
   worker) the Linux host sees the key during signing: a test deployment. With the MP-SPDZ
   backend the engines run a real three-party computation, semi-honest only, verified on one
   macOS machine and not on Linux or across hosts (`mpc/mp-spdz/README.md`).
3. **All root engines are on the Linux host**, so that host is a single point for session-time
   secrecy regardless of the backend. Spreading the engines over three operators is the point of
   having three; this layout is for testing the network path.

The examples use `10.8.0.1` for the Mac and `10.8.0.2` for the Linux server (tunnel addresses).

## 1. Build on both hosts

```bash
git clone https://github.com/exocognosis/cairn.git && cd cairn && cargo build --release -p cairn-sidecar
```

## 2. Keys and address book (Mac)

```bash
target/release/cairn keygen --out keys
```

Replace the generated loopback address book with the real one:

```bash
{
  echo "{"
  port=7100
  for leaf in 1 2 3 4; do for s in 1 2 3 4; do
    host=10.8.0.2; [ "$leaf" = 1 ] && host=10.8.0.1
    echo "  \"leaf_${leaf}/signer_${s}\": \"${host}:${port}\","; port=$((port + 1))
  done; done
  echo '  "root_1": "10.8.0.2:7116", "root_2": "10.8.0.2:7117", "root_3": "10.8.0.2:7118", "root_4": "10.8.0.2:7119"'
  echo "}"
} > keys/peers.json
```

Send the Linux host its files (its shares, its nodes' certificates and keys, the CA and the
fingerprint table), then remove its secrets from the Mac:

```bash
ssh linux 'mkdir -p cairn/keys/tls' && scp keys/group.bin keys/peers.json keys/leaf_[234]_*.share linux:cairn/keys/ && scp keys/tls/ca.pem keys/tls/fingerprints.json keys/tls/leaf_[234]_* keys/tls/root_* linux:cairn/keys/tls/
```

```bash
rm -P keys/leaf_[234]_*.share keys/tls/leaf_[234]_*.key keys/tls/root_*.key
```

A trusted dealer on one machine is a v2 limitation: the Mac held the whole key during `keygen`.

## 3. Linux: MPC backend, root engines, leaves B to D

Reference backend (test deployments):

```bash
mkdir -p /run/cairn && nohup target/release/cairn mpc-worker --socket-dir /run/cairn > logs-mpc.txt 2>&1 &
```

For MP-SPDZ instead, start `mpc/mp-spdz/run_bridge.sh` for parties 1 to 3 with the same socket
directory (see its README) and raise `--mpc-timeout-ms` on the root engines and on `serve-kms`.

Root engines:

```bash
for k in 1 2 3 4; do nohup target/release/cairn node --role root --id root_$k --bind 10.8.0.2:$((7115 + k)) --peers keys/peers.json --group keys/group.bin --tls keys/tls --mpc-socket-dir /run/cairn > logs-root_$k.txt 2>&1 & done
```

Signers of leaves 2 to 4:

```bash
port=7104; for leaf in 2 3 4; do for s in 1 2 3 4; do nohup target/release/cairn node --role signer --id leaf_$leaf/signer_$s --bind 10.8.0.2:$port --peers keys/peers.json --group keys/group.bin --tls keys/tls --share keys/leaf_${leaf}_signer_$s.share > logs-leaf_${leaf}_signer_$s.txt 2>&1 & port=$((port + 1)); done; done
```

CometBFT runs as usual on this host with its RPC reachable from the Mac over the tunnel
(`rpc.laddr = "tcp://10.8.0.2:26657"`).

## 4. Mac: leaf A, coordinator, pqc-sidecar

Signers of leaf 1:

```bash
for s in 1 2 3 4; do nohup target/release/cairn node --role signer --id leaf_1/signer_$s --bind 10.8.0.1:$((7099 + s)) --peers keys/peers.json --group keys/group.bin --tls keys/tls --share keys/leaf_1_signer_$s.share > logs-leaf_1_signer_$s.txt 2>&1 & done
```

Coordinator and KMS-compatible endpoint (loopback: only the local sidecar talks to it):

```bash
nohup target/release/cairn serve-kms --listen 127.0.0.1:8200 --peers keys/peers.json --group keys/group.bin --tls keys/tls --public-key-out public_key.hex --round-timeout-ms 3000 > logs-serve-kms.txt 2>&1 &
```

pqc-sidecar, unmodified, with this `config.toml`:

```toml
[signer]
backend = "aws_kms"
aws_kms_key_id = "alias/cairn-tower"
aws_region = "us-east-1"
aws_endpoint_url = "http://127.0.0.1:8200"
public_key_file = "public_key.hex"

[chain]
adapter = "cometbft"
id = "cosmos:<your-chain-id>"
rpc_url = "http://10.8.0.2:26657"
verify = "light"

[checkpoint]
interval = 100

[telemetry]
listen = "127.0.0.1:9100"

[output]
certificate_dir = "certs"
```

```bash
AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_EC2_METADATA_DISABLED=true pqc-sidecar --config config.toml
```

The credentials are placeholders: the endpoint is on loopback and ignores request signatures.

## 5. Check

```bash
pqc-sidecar verify --certificate certs/<height>.pqcc --public-key public_key.hex
```

`logs-serve-kms.txt` on the Mac and the node logs on both hosts show nothing per signature in
v2; faults surface as pqc-sidecar signing errors (`KMSInternalException` with the fault list).

## Timeouts

| Flag | Where | Default | Set it to |
|---|---|---|---|
| `--round-timeout-ms` | nodes, `serve-kms` | 2000 | several times the link round trip (each exchange is a TCP and a TLS handshake plus the request) |
| `--mpc-timeout-ms` | root engines, `serve-kms` | 30000 | longer than one MPC phase of your backend |

A signer's deal includes three nested exchanges with the engines; the coordinator allows it two
round timeouts.

## Stopping

```bash
pkill -f "cairn (node|serve-kms|mpc-worker)"
```

## 6. The layout that was actually run: loopback plus SSH forwards

Only the Mac opens connections, so nothing needs to listen on a public or tunnel address:
every node binds to loopback on its own host, both hosts use the same address book, and the Mac
forwards the server's node ports over SSH.

On the Mac:

```bash
target/release/cairn keygen --out target/split/keys --base-port 17100
```

Copy the Linux binary (cross-compiled with `cargo zigbuild --release -p cairn-sidecar --target
x86_64-unknown-linux-gnu.2.35`), the server's key files as in section 2, `mpc/mp-spdz/*` and
`scripts/split-host/remote.sh` to `/root/cairn/` on the server. Then on the server:

```bash
/root/cairn/remote.sh start reference
```

(`start mpspdz` instead uses the MP-SPDZ bridges; it expects MP-SPDZ built in `/root/MP-SPDZ`.)
And on the Mac:

```bash
scripts/split-host/local.sh start root@<server>
```

```bash
target/release/cairn remote-bench --peers target/split/keys/peers.json --group target/split/keys/group.bin --tls target/split/keys/tls --signatures 50
```

For MP-SPDZ pass a long MPC deadline: `local.sh start root@<server> 900000` and
`remote-bench ... --mpc-timeout-ms 900000`. The KMS endpoint is on `127.0.0.1:18200` and the
chain stand-in on `127.0.0.1:18657` for the pqc-sidecar configuration of section 4.
`local.sh stop` and `remote.sh stop` end the run.
