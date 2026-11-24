#!/usr/bin/env bash
# Mac side of a split-host cluster: SSH port forwards to the Linux host, leaf 1 (4 signers),
# and `cairn serve-kms` as coordinator. See DEPLOY_SPLIT.md.
#
#   local.sh start <user@host> [mpc-timeout-ms]     local.sh stop
#
# Uses target/split/keys (cairn keygen --out target/split/keys --base-port 17100).
set -euo pipefail
cd "$(dirname "$0")/../.."
BASE="${BASE:-17100}" KMS="${KMS:-18200}" RPC="${RPC:-18657}" DIR=target/split
CAIRN="$PWD/target/release/cairn"
case "${1:-}" in
stop)
  pkill -f "cairn-split-forward" 2>/dev/null || true
  pkill -f "$CAIRN (node|serve-kms)" 2>/dev/null || true
  echo stopped;;
start)
  HOST="${2:?user@host}" MPC_MS="${3:-30000}"
  "$0" stop > /dev/null
  mkdir -p "$DIR/logs"
  FWD=(); for p in $(seq $((BASE + 4)) $((BASE + 19))) "$RPC"; do FWD+=(-L "$p:127.0.0.1:$p"); done
  # The tag in -o SetEnv only labels the process so `stop` can find it.
  ssh -f -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 \
      -o SetEnv=TAG=cairn-split-forward "${FWD[@]}" "$HOST"
  for s in 1 2 3 4; do
    nohup "$CAIRN" node --role signer --id "leaf_1/signer_$s" --bind "127.0.0.1:$((BASE + s - 1))" \
      --peers "$DIR/keys/peers.json" --group "$DIR/keys/group.bin" --tls "$DIR/keys/tls" \
      --share "$DIR/keys/leaf_1_signer_$s.share" --round-timeout-ms 5000 > "$DIR/logs/leaf_1_signer_$s.log" 2>&1 &
  done
  nohup "$CAIRN" serve-kms --listen "127.0.0.1:$KMS" --peers "$DIR/keys/peers.json" \
    --group "$DIR/keys/group.bin" --tls "$DIR/keys/tls" --public-key-out "$DIR/public_key.hex" \
    --round-timeout-ms 5000 --mpc-timeout-ms "$MPC_MS" > "$DIR/logs/serve-kms.log" 2>&1 &
  for _ in $(seq 100); do nc -z 127.0.0.1 "$KMS" 2>/dev/null && break; sleep 0.1; done
  echo "up: leaf 1 and coordinator here, KMS endpoint http://127.0.0.1:$KMS, forwards to $HOST";;
*) echo "usage: local.sh start <user@host> [mpc-timeout-ms] | stop" >&2; exit 2;;
esac
