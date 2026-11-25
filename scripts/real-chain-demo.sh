#!/usr/bin/env bash
# Sign checkpoints of a real public chain: an unmodified pqc-sidecar follows Cosmos Hub through
# a public RPC endpoint, verifies each block's validator signatures itself (light-client
# mode), and has a local cairn committee (key generated jointly, no dealer) sign every tenth
# block. Nothing is sent to the chain; the script only reads from it.
#
#   scripts/real-chain-demo.sh [certificates=2]
#
# Needs scripts/setup-verifiers.sh (or PQC_SIDECAR_BIN) and network access.
set -euo pipefail
cd "$(dirname "$0")/.."
WANT="${1:-2}"
SIDECAR="${PQC_SIDECAR_BIN:-$PWD/target/pqc-sidecar/release/pqc-sidecar}"
RPC="${COSMOS_RPC:-https://cosmos-rpc.publicnode.com}"
CHAIN="cosmos:cosmoshub-4"
DIR="$PWD/target/real-chain" KMS="${CAIRN_KMS_PORT:-18210}"
[ -x "$SIDECAR" ] || { echo "pqc-sidecar binary not found: run scripts/setup-verifiers.sh" >&2; exit 1; }
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT

# Local credentials for the KMS endpoint, shared with the sidecar below.
export CAIRN_KMS_ACCESS_KEY_ID=cairn-demo CAIRN_KMS_SECRET_ACCESS_KEY="$(head -c 24 /dev/urandom | base64)"
scripts/run_local_committee.sh --committee 3-of-4 --dir "$DIR" --base-port 17400 --kms-port "$KMS" \
  --chains "$CHAIN" > "$DIR.committee.log" 2>&1 & PIDS+=($!)
for _ in $(seq 600); do grep -q '^ready$' "$DIR.committee.log" 2>/dev/null && break; sleep 0.2; done
grep -q '^ready$' "$DIR.committee.log" || { cat "$DIR.committee.log"; echo "committee did not start" >&2; exit 1; }

mkdir -p "$DIR/sidecar"
cat > "$DIR/sidecar/config.toml" <<TOML
[signer]
backend = "aws_kms"
aws_kms_key_id = "alias/cairn-committee"
aws_region = "us-east-1"
aws_endpoint_url = "http://127.0.0.1:$KMS"
public_key_file = "$DIR/sidecar/public_key.hex"

[chain]
adapter = "cometbft"
id = "$CHAIN"
rpc_url = "$RPC"
poll_interval_ms = 2000
request_timeout_ms = 10000
start_height = 0
verify = "light"

[checkpoint]
interval = 10

[telemetry]
listen = "127.0.0.1:$((KMS + 1))"

[output]
certificate_dir = "$DIR/sidecar/certs"
TOML
export AWS_ACCESS_KEY_ID="$CAIRN_KMS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$CAIRN_KMS_SECRET_ACCESS_KEY" AWS_EC2_METADATA_DISABLED=true
"$SIDECAR" kms-public-key --config "$DIR/sidecar/config.toml" --public-key-out "$DIR/sidecar/public_key.hex" > /dev/null
"$SIDECAR" --config "$DIR/sidecar/config.toml" > "$DIR/logs/pqc-sidecar.log" 2>&1 & PIDS+=($!)
echo "following $CHAIN via $RPC; waiting for $WANT certificates (one per 10 blocks, about a minute each)"
for _ in $(seq 900); do
  have=$(ls "$DIR/sidecar/certs" 2>/dev/null | grep -c '\.pqcc$' || true)
  [ "$have" -ge "$WANT" ] && break
  sleep 1
done
[ "${have:-0}" -ge "$WANT" ] || { tail -5 "$DIR/logs/pqc-sidecar.log"; echo "only ${have:-0} certificates" >&2; exit 1; }
for cert in "$DIR"/sidecar/certs/*.pqcc; do
  "$SIDECAR" verify --certificate "$cert" --public-key "$DIR/sidecar/public_key.hex"
done
echo "OK: $have Cosmos Hub checkpoints signed by a 3-of-4 committee and verified by unmodified pqc-sidecar"
