#!/usr/bin/env bash
# Point the unmodified pqc-sidecar binary's aws_kms signer backend at the tower.
# Checks that pqc-sidecar's own KMS client reads the tower's public key from the endpoint.
# Run scripts/setup-verifiers.sh first.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${CAIRN_KMS_PORT:-18200}"
WORK="target/kms-interop"
rm -rf "$WORK" && mkdir -p "$WORK/certs"
cargo build --quiet --release -p cairn-sidecar
target/release/cairn serve-kms --listen "127.0.0.1:$PORT" --public-key-out "$WORK/tower_public_key.hex" &
KMS=$!
trap 'kill $KMS 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -s "$WORK/tower_public_key.hex" ] && break; sleep 0.1; done
cat > "$WORK/config.toml" <<TOML
[signer]
backend = "aws_kms"
aws_kms_key_id = "alias/cairn-tower"
aws_region = "us-east-1"
aws_endpoint_url = "http://127.0.0.1:$PORT"
public_key_file = "$PWD/$WORK/public_key.hex"
[chain]
adapter = "cometbft"
id = "cosmos:cairn-devnet-1"
rpc_url = "http://127.0.0.1:26657"
[checkpoint]
interval = 100
[telemetry]
listen = "127.0.0.1:19100"
[output]
certificate_dir = "$PWD/$WORK/certs"
TOML
# Placeholder credentials: the endpoint is local and ignores request signatures.
AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_EC2_METADATA_DISABLED=true \
  target/pqc-sidecar/release/pqc-sidecar kms-public-key --config "$WORK/config.toml" \
  --public-key-out "$WORK/public_key.hex"
cmp "$WORK/public_key.hex" "$WORK/tower_public_key.hex"
echo "OK: unmodified pqc-sidecar read the tower public key through its aws_kms backend"
