#!/usr/bin/env bash
# Run a flat committee (the three-round protocol, no MPC) on this machine as separate OS
# processes over mutual TLS, with `cairn serve-kms` as coordinator and KMS-compatible endpoint.
#
#   scripts/run_local_committee.sh [--committee 3-of-4] [--dir DIR] [--base-port 7300]
#                                  [--kms-port 8200] [--rtt-ms 0] [--chains cosmos:cosmoshub-4]
#                                  [--metrics-base PORT]
#
# --metrics-base serves Prometheus metrics: the coordinator on PORT, party k on PORT+k.
#
# --chains restricts what every party will sign. Set CAIRN_KMS_ACCESS_KEY_ID and
# CAIRN_KMS_SECRET_ACCESS_KEY to require signed (AWS SigV4) requests on the KMS endpoint.
#
# Stop with Ctrl-C. Research prototype: see docs/PRODUCTION_PATH.md for what is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
SPEC=3-of-4 DIR=target/local-committee BASE=7300 KMS=8200 RTT=0 CHAINS="" METRICS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --committee) SPEC="$2";; --dir) DIR="$2";; --base-port) BASE="$2";;
    --kms-port) KMS="$2";; --rtt-ms) RTT="$2";; --chains) CHAINS="$2";;
    --metrics-base) METRICS="$2";;
    *) echo "unknown option $1" >&2; exit 2;;
  esac; shift 2
done
N="${SPEC##*-of-}"
cargo build --quiet --release -p cairn-sidecar
CAIRN="$PWD/target/release/cairn"
rm -rf "$DIR" && mkdir -p "$DIR/logs"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT INT TERM
# Distributed key generation: each party gets its own identity and working directory, the
# parties generate the key together, and no process ever holds all of it.
"$CAIRN" committee-init --out "$DIR/keys" --committee "$SPEC" --base-port "$BASE" > "$DIR/init.json"
DKG=()
for k in $(seq "$N"); do
  "$CAIRN" dkg-party --id "party_$k" --bind "127.0.0.1:$((BASE + k - 1))" --roster "$DIR/keys/roster.json" \
    --identity "$DIR/keys/party_$k/identity.pk8" --tls "$DIR/keys/tls" --out "$DIR/keys/party_$k" \
    2> "$DIR/logs/dkg_party_$k.log" & DKG+=($!)
done
for k in $(seq "$N"); do
  for _ in $(seq 100); do nc -z 127.0.0.1 "$((BASE + k - 1))" 2>/dev/null && break; sleep 0.1; done
done
"$CAIRN" dkg --roster "$DIR/keys/roster.json" --peers "$DIR/keys/peers.json" --tls "$DIR/keys/tls" > "$DIR/dkg.json"
wait "${DKG[@]}"
cp "$DIR/keys/party_1/committee.bin" "$DIR/keys/committee.bin"
for k in $(seq "$N"); do
  "$CAIRN" node --role party --id "party_$k" --bind "127.0.0.1:$((BASE + k - 1))" \
    --peers "$DIR/keys/peers.json" --committee "$DIR/keys/party_$k/committee.bin" --tls "$DIR/keys/tls" \
    --share "$DIR/keys/party_$k/party_$k.share" --state "$DIR/party_$k.state.json" \
    --audit-log "$DIR/logs/party_$k.audit.log" ${CHAINS:+--chains "$CHAINS"} ${METRICS:+--metrics-listen "127.0.0.1:$((METRICS + k))"} --link-delay-ms $((RTT / 2)) 2> "$DIR/logs/party_$k.log" & PIDS+=($!)
done
"$CAIRN" serve-kms --listen "127.0.0.1:$KMS" --peers "$DIR/keys/peers.json" \
  --committee "$DIR/keys/committee.bin" --tls "$DIR/keys/tls" \
  --public-key-out "$DIR/public_key.hex" ${CAIRN_KMS_ACCESS_KEY_ID:+--access-key-id "$CAIRN_KMS_ACCESS_KEY_ID"} ${METRICS:+--metrics-listen "127.0.0.1:$METRICS"} --link-delay-ms $((RTT / 2)) 2> "$DIR/logs/serve-kms.log" & PIDS+=($!)
for _ in $(seq 100); do nc -z 127.0.0.1 "$KMS" 2>/dev/null && break; sleep 0.1; done
echo "cairn committee up: $SPEC (ports $BASE-$((BASE + N - 1)))"
echo "KMS endpoint:       http://127.0.0.1:$KMS   (pqc-sidecar: signer.aws_endpoint_url)"
echo "public key:         $DIR/public_key.hex"
echo "ready"
wait
