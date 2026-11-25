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

# Same call over HTTPS with signed requests: the sidecar trusts the endpoint's certificate
# through SSL_CERT_FILE and is refused without it.
kill $KMS 2>/dev/null || true
TLS_PORT=$((PORT + 1))
rm -f "$WORK/tower_public_key.hex" "$WORK/public_key.hex"
target/release/cairn kms-cert --out "$WORK/tls" >/dev/null
CAIRN_KMS_SECRET_ACCESS_KEY=interop-secret target/release/cairn serve-kms \
  --listen "127.0.0.1:$TLS_PORT" --public-key-out "$WORK/tower_public_key.hex" \
  --access-key-id AKIACAIRNINTEROP --tls-cert "$WORK/tls/kms.pem" --tls-key "$WORK/tls/kms.key" &
KMS=$!
for _ in $(seq 50); do [ -s "$WORK/tower_public_key.hex" ] && break; sleep 0.1; done
sed -i.bak "s#http://127.0.0.1:$PORT#https://localhost:$TLS_PORT#" "$WORK/config.toml"
sidecar() {
  AWS_ACCESS_KEY_ID=AKIACAIRNINTEROP AWS_SECRET_ACCESS_KEY=interop-secret AWS_EC2_METADATA_DISABLED=true \
    "$@" target/pqc-sidecar/release/pqc-sidecar kms-public-key --config "$WORK/config.toml" \
    --public-key-out "$WORK/public_key.hex"
}
if sidecar env >/dev/null 2>&1; then echo "FAIL: accepted an untrusted certificate"; exit 1; fi
sidecar env SSL_CERT_FILE="$PWD/$WORK/tls/kms.pem"
cmp "$WORK/public_key.hex" "$WORK/tower_public_key.hex"
echo "OK: same over HTTPS with SigV4; refused without the certificate as trust root"
