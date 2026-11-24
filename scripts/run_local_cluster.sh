#!/usr/bin/env bash
# Run the whole tower on this machine as separate OS processes over TCP:
#   16 signer nodes (four 3-of-4 leaf committees), 4 root MPC engine nodes (3 active, 1 spare),
#   the reference MPC worker, and `cairn serve-kms` as coordinator and KMS-compatible endpoint.
#
#   scripts/run_local_cluster.sh [--dir DIR] [--base-port 7100] [--kms-port 8200]
#                                [--rtt-ms 0] [--fault leaf_1/signer_1=stall,...]
#
# Set CAIRN_MPC_SOCKET_DIR to use an MPC backend that is already running there (for example the
# MP-SPDZ bridges of mpc/mp-spdz/run_bridge.sh) instead of the reference worker, and
# CAIRN_MPC_TIMEOUT_MS to give its phases time (default 30000; 900000 when a backend is given).
#
# Stop with Ctrl-C. Logs and keys are under DIR (default target/local-cluster).
# The MPC worker is the clear-text reference backend: this is a test cluster, not custody.
set -euo pipefail
cd "$(dirname "$0")/.."
DIR=target/local-cluster BASE=7100 KMS=8200 RTT=0 FAULTS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2";; --base-port) BASE="$2";; --kms-port) KMS="$2";;
    --rtt-ms) RTT="$2";; --fault) FAULTS="$2";;
    *) echo "unknown option $1" >&2; exit 2;;
  esac; shift 2
done
cargo build --quiet --release -p cairn-sidecar
CAIRN="$PWD/target/release/cairn"
rm -rf "$DIR" && mkdir -p "$DIR/logs"
EXTERNAL="${CAIRN_MPC_SOCKET_DIR:-}"
if [ -n "$EXTERNAL" ]; then SOCK="$EXTERNAL"; else SOCK="$(mktemp -d /tmp/cairn-mpc.XXXXXX)"; fi   # short path
MPC_MS="${CAIRN_MPC_TIMEOUT_MS:-$([ -n "$EXTERNAL" ] && echo 900000 || echo 30000)}"
DELAY=$((RTT / 2))
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; [ -n "$EXTERNAL" ] || rm -rf "$SOCK"; }
trap cleanup EXIT INT TERM

"$CAIRN" keygen --out "$DIR/keys" --base-port "$BASE" > "$DIR/keygen.json"
if [ -z "$EXTERNAL" ]; then
  "$CAIRN" mpc-worker --socket-dir "$SOCK" 2> "$DIR/logs/mpc-worker.log" & PIDS+=($!)
fi

fault_of() { echo ",$FAULTS," | sed -n "s#.*,$1=\([a-z-]*\),.*#\1#p"; }
port=$BASE
for leaf in 1 2 3 4; do for signer in 1 2 3 4; do
  id="leaf_${leaf}/signer_${signer}"; f="$(fault_of "$id")"
  "$CAIRN" node --role signer --id "$id" --bind "127.0.0.1:$port" \
    --peers "$DIR/keys/peers.json" --group "$DIR/keys/group.bin" \
    --share "$DIR/keys/leaf_${leaf}_signer_${signer}.share" \
    --link-delay-ms "$DELAY" --fault "${f:-none}" 2> "$DIR/logs/leaf_${leaf}_signer_${signer}.log" & PIDS+=($!)
  port=$((port + 1))
done; done
for root in 1 2 3 4; do
  id="root_${root}"; f="$(fault_of "$id")"
  "$CAIRN" node --role root --id "$id" --bind "127.0.0.1:$port" \
    --peers "$DIR/keys/peers.json" --group "$DIR/keys/group.bin" --mpc-socket-dir "$SOCK" --mpc-timeout-ms "$MPC_MS" \
    --link-delay-ms "$DELAY" --fault "${f:-none}" 2> "$DIR/logs/root_${root}.log" & PIDS+=($!)
  port=$((port + 1))
done
"$CAIRN" serve-kms --listen "127.0.0.1:$KMS" --peers "$DIR/keys/peers.json" --group "$DIR/keys/group.bin" \
  --public-key-out "$DIR/public_key.hex" --mpc-timeout-ms "$MPC_MS" --link-delay-ms "$DELAY" 2> "$DIR/logs/serve-kms.log" & PIDS+=($!)

for _ in $(seq 100); do nc -z 127.0.0.1 "$KMS" 2>/dev/null && break; sleep 0.1; done
echo "cairn cluster up: 16 signers + 4 root engines + MPC worker (ports $BASE-$((port - 1)))"
echo "KMS endpoint:     http://127.0.0.1:$KMS   (pqc-sidecar: signer.aws_endpoint_url)"
echo "public key:       $DIR/public_key.hex"
echo "ready"
wait
