#!/usr/bin/env bash
# Run a flat committee (the three-round protocol, no MPC) on this machine as separate OS
# processes over mutual TLS, with `cairn serve-kms` as coordinator and KMS-compatible endpoint.
#
#   scripts/run_local_committee.sh [--committee 3-of-4] [--dir DIR] [--base-port 7300]
#                                  [--kms-port 8200] [--rtt-ms 0]
#
# Stop with Ctrl-C. Research prototype: see docs/PRODUCTION_PATH.md for what is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
SPEC=3-of-4 DIR=target/local-committee BASE=7300 KMS=8200 RTT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --committee) SPEC="$2";; --dir) DIR="$2";; --base-port) BASE="$2";;
    --kms-port) KMS="$2";; --rtt-ms) RTT="$2";;
    *) echo "unknown option $1" >&2; exit 2;;
  esac; shift 2
done
N="${SPEC##*-of-}"
cargo build --quiet --release -p cairn-sidecar
CAIRN="$PWD/target/release/cairn"
rm -rf "$DIR" && mkdir -p "$DIR/logs"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT INT TERM
"$CAIRN" keygen --out "$DIR/keys" --committee "$SPEC" --base-port "$BASE" > "$DIR/keygen.json"
for k in $(seq "$N"); do
  "$CAIRN" node --role party --id "party_$k" --bind "127.0.0.1:$((BASE + k - 1))" \
    --peers "$DIR/keys/peers.json" --committee "$DIR/keys/committee.bin" --tls "$DIR/keys/tls" \
    --share "$DIR/keys/party_$k.share" --state "$DIR/party_$k.state.json" \
    --audit-log "$DIR/logs/party_$k.audit.log" --link-delay-ms $((RTT / 2)) 2> "$DIR/logs/party_$k.log" & PIDS+=($!)
done
"$CAIRN" serve-kms --listen "127.0.0.1:$KMS" --peers "$DIR/keys/peers.json" \
  --committee "$DIR/keys/committee.bin" --tls "$DIR/keys/tls" \
  --public-key-out "$DIR/public_key.hex" --link-delay-ms $((RTT / 2)) 2> "$DIR/logs/serve-kms.log" & PIDS+=($!)
for _ in $(seq 100); do nc -z 127.0.0.1 "$KMS" 2>/dev/null && break; sleep 0.1; done
echo "cairn committee up: $SPEC (ports $BASE-$((BASE + N - 1)))"
echo "KMS endpoint:       http://127.0.0.1:$KMS   (pqc-sidecar: signer.aws_endpoint_url)"
echo "public key:         $DIR/public_key.hex"
echo "ready"
wait
