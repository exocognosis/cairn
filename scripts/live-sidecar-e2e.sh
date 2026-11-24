#!/usr/bin/env bash
# Live end to end: an unmodified pqc-sidecar daemon signs a checkpoint through a cairn cluster
# of separate processes (GetPublicKey and Sign over its aws_kms backend), writes a .pqcc
# certificate, and the unmodified verifier accepts it and rejects a tampered copy.
# Needs scripts/setup-verifiers.sh to have been run (or PQC_SIDECAR_BIN set).
set -euo pipefail
cd "$(dirname "$0")/.."
SIDECAR="${PQC_SIDECAR_BIN:-$PWD/target/pqc-sidecar/release/pqc-sidecar}"
[ -x "$SIDECAR" ] || { echo "pqc-sidecar binary not found: run scripts/setup-verifiers.sh" >&2; exit 1; }
DIR="$PWD/target/live-e2e" KMS="${CAIRN_KMS_PORT:-18200}" RPC="${CAIRN_RPC_PORT:-18657}" BASE="${CAIRN_BASE_PORT:-17100}"
CHAIN=cairn-devnet-1
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT

scripts/run_local_cluster.sh --dir "$DIR" --base-port "$BASE" --kms-port "$KMS" > "$DIR.cluster.log" 2>&1 & PIDS+=($!)
for _ in $(seq 600); do grep -q '^ready$' "$DIR.cluster.log" 2>/dev/null && break; sleep 0.2; done
grep -q '^ready$' "$DIR.cluster.log" || { cat "$DIR.cluster.log"; echo "cluster did not start" >&2; exit 1; }
target/release/cairn mock-chain --listen "127.0.0.1:$RPC" --chain-id "$CHAIN" --height 150 2> "$DIR/logs/mock-chain.log" & PIDS+=($!)
for _ in $(seq 50); do nc -z 127.0.0.1 "$RPC" 2>/dev/null && break; sleep 0.1; done

mkdir -p "$DIR/sidecar"
cat > "$DIR/sidecar/config.toml" <<TOML
[signer]
backend = "aws_kms"
aws_kms_key_id = "alias/cairn-tower"
aws_region = "us-east-1"
aws_endpoint_url = "http://127.0.0.1:$KMS"
public_key_file = "$DIR/sidecar/public_key.hex"

[chain]
adapter = "cometbft"
id = "cosmos:$CHAIN"
rpc_url = "http://127.0.0.1:$RPC"
poll_interval_ms = 200
start_height = 100
verify = "trust_node"

[checkpoint]
interval = 100

[telemetry]
listen = "127.0.0.1:$((RPC + 1))"

[output]
certificate_dir = "$DIR/sidecar/certs"
TOML
# Placeholder credentials: the endpoint is local and ignores request signatures.
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_EC2_METADATA_DISABLED=true

"$SIDECAR" kms-public-key --config "$DIR/sidecar/config.toml" --public-key-out "$DIR/sidecar/public_key.hex" > /dev/null
cmp "$DIR/sidecar/public_key.hex" "$DIR/public_key.hex"
echo "GetPublicKey: stock pqc-sidecar read the tower public key"

"$SIDECAR" --config "$DIR/sidecar/config.toml" > "$DIR/logs/pqc-sidecar.log" 2>&1 & PIDS+=($!)
CERT="$DIR/sidecar/certs/00000000000000000100.pqcc"
for _ in $(seq "${CAIRN_CERT_WAIT_TICKS:-300}"); do [ -s "$CERT" ] && break; sleep 0.2; done
[ -s "$CERT" ] || { tail -5 "$DIR/logs/pqc-sidecar.log"; echo "no certificate written" >&2; exit 1; }
echo "Sign: stock pqc-sidecar wrote $CERT"

"$SIDECAR" verify --certificate "$CERT" --public-key "$DIR/sidecar/public_key.hex"
python3 - "$CERT" "$DIR/sidecar/tampered.pqcc" <<'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read()); b[-3000] ^= 1
open(sys.argv[2], "wb").write(b)
PY
if "$SIDECAR" verify --certificate "$DIR/sidecar/tampered.pqcc" --public-key "$DIR/sidecar/public_key.hex" > /dev/null 2>&1; then
  echo "tampered certificate was accepted" >&2; exit 1
fi
echo "OK: certificate verified by unmodified pqc-sidecar; tampered copy rejected"
