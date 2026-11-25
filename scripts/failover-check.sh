#!/usr/bin/env bash
# Coordinator failover, end to end: an unmodified pqc-sidecar talks to `cairn kms-failover`,
# which fronts two coordinators (the standby set up as in docs/OPERATIONS.md, with its own
# certificate pinned by the running parties). The active coordinator is killed, then brought
# back while the other is killed; the sidecar must get a certificate for every checkpoint and
# all of them must verify under the one committee key.
# Needs scripts/setup-verifiers.sh to have been run (or PQC_SIDECAR_BIN set).
set -euo pipefail
cd "$(dirname "$0")/.."
SIDECAR="${PQC_SIDECAR_BIN:-$PWD/target/pqc-sidecar/release/pqc-sidecar}"
[ -x "$SIDECAR" ] || { echo "pqc-sidecar binary not found: run scripts/setup-verifiers.sh" >&2; exit 1; }
DIR="$PWD/target/failover-check" KMS_A=18230 KMS_B=18231 FRONT=18232 RPC=18687 BASE=17330 CHAIN=cairn-devnet-1
CAIRN="$PWD/target/release/cairn"
rm -rf "$DIR" "$DIR.committee.log"
PIDS=() MOCK="" A="" B=""
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
port() { for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never opened" >&2; exit 1; }

# The committee, with its first coordinator on KMS_A.
scripts/run_local_committee.sh --dir "$DIR" --base-port "$BASE" --kms-port "$KMS_A" > "$DIR.committee.log" 2>&1 & PIDS+=($!)
for _ in $(seq 600); do grep -q '^ready$' "$DIR.committee.log" 2>/dev/null && break; sleep 0.2; done
grep -q '^ready$' "$DIR.committee.log" || { cat "$DIR.committee.log"; echo "committee did not start" >&2; exit 1; }
A=$(pgrep -f "serve-kms --listen 127.0.0.1:$KMS_A" | head -1)

# The standby: its own certificate, made in its own directory, pinned by the running parties.
mkdir -p "$DIR/standby-tls" "$DIR/sidecar"
cp "$DIR/keys/tls/fingerprints.json" "$DIR/standby-tls/"
FP=$("$CAIRN" tls-rotate --tls "$DIR/standby-tls" --id coordinator | python3 -c 'import json,sys; print(json.load(sys.stdin)["fingerprint"])')
"$CAIRN" tls-pin --tls "$DIR/keys/tls" --id coordinator --fingerprint "$FP" > /dev/null
coordinator() { # coordinator <port> <tls dir>
  "$CAIRN" serve-kms --listen "127.0.0.1:$1" --peers "$DIR/keys/peers.json" \
    --committee "$DIR/keys/committee.bin" --tls "$2" 2>> "$DIR/logs/serve-kms-$1.log" &
  PIDS+=($!); port "$1"
}
coordinator "$KMS_B" "$DIR/standby-tls"; B=$!
"$CAIRN" kms-failover --listen "127.0.0.1:$FRONT" --backends "127.0.0.1:$KMS_A,127.0.0.1:$KMS_B" \
  2> "$DIR/logs/kms-failover.log" & PIDS+=($!)
port "$FRONT"

cat > "$DIR/sidecar/config.toml" <<TOML
[signer]
backend = "aws_kms"
aws_kms_key_id = "alias/cairn-tower"
aws_region = "us-east-1"
aws_endpoint_url = "http://127.0.0.1:$FRONT"
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
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_EC2_METADATA_DISABLED=true
"$SIDECAR" kms-public-key --config "$DIR/sidecar/config.toml" --public-key-out "$DIR/sidecar/public_key.hex" > /dev/null
cmp "$DIR/sidecar/public_key.hex" "$DIR/public_key.hex"

HEIGHT=0
next_certificate() {
  HEIGHT=$((HEIGHT + 100))
  [ -n "$MOCK" ] && { kill "$MOCK"; wait "$MOCK" 2>/dev/null || true; }
  "$CAIRN" mock-chain --listen "127.0.0.1:$RPC" --chain-id "$CHAIN" --height "$((HEIGHT + 50))" 2>> "$DIR/logs/mock-chain.log" &
  MOCK=$!; PIDS+=($!)
  local cert start; cert="$DIR/sidecar/certs/$(printf '%020d' "$HEIGHT").pqcc"; start=$(date +%s)
  for _ in $(seq 300); do [ -s "$cert" ] && break; sleep 0.2; done
  [ -s "$cert" ] || { tail -5 "$DIR/logs/pqc-sidecar.log"; echo "no certificate at height $HEIGHT: $1" >&2; exit 1; }
  "$SIDECAR" verify --certificate "$cert" --public-key "$DIR/sidecar/public_key.hex" > /dev/null
  echo "height $HEIGHT certified within $(( $(date +%s) - start + 1 )) s: $1"
}
"$CAIRN" mock-chain --listen "127.0.0.1:$RPC" --chain-id "$CHAIN" --height 50 2>> "$DIR/logs/mock-chain.log" & MOCK=$!; PIDS+=($!)
port "$RPC"
"$SIDECAR" --config "$DIR/sidecar/config.toml" > "$DIR/logs/pqc-sidecar.log" 2>&1 & PIDS+=($!)
next_certificate "both coordinators up"
kill "$A"; wait "$A" 2>/dev/null || true
next_certificate "first coordinator killed, standby took over"
next_certificate "still on the standby"
coordinator "$KMS_A" "$DIR/keys/tls"
kill "$B"; wait "$B" 2>/dev/null || true
next_certificate "standby killed, first coordinator back"
grep -c "now using" "$DIR/logs/kms-failover.log" | xargs -I{} echo "relay switched backend {} times"
echo "OK: the sidecar kept getting certificates through two coordinator failures"
