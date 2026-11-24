#!/usr/bin/env bash
# Linux side of a split-host cluster: leaves 2 to 4 (12 signers), 4 root engines, the MPC
# backend and a CometBFT RPC stand-in. Everything binds to loopback; the Mac reaches it through
# SSH port forwards (scripts/split-host/local.sh), so no firewall port is opened.
#
#   remote.sh start [reference|mpspdz]     remote.sh stop
#
# Layout expected under /root/cairn: cairn (binary), keys/ (group.bin, peers.json, this host's
# .share files, tls/), mp-spdz/ (bridge files). BASE must match the address book.
set -euo pipefail
cd /root/cairn
BASE="${BASE:-17100}" SOCK=/run/cairn-mpc RPC="${RPC:-18657}"
MPC_MS="${MPC_MS:-30000}"
case "${1:-}" in
stop)
  pkill -f "/root/cairn/cairn" 2>/dev/null || true
  pkill -f "bridge.py" 2>/dev/null || true
  pkill -f "party.x" 2>/dev/null || true
  rm -rf "$SOCK"; echo stopped;;
start)
  "$0" stop > /dev/null
  mkdir -p "$SOCK" logs
  if [ "${2:-reference}" = mpspdz ]; then
    MPC_MS=900000
    (cd mp-spdz && MPSPDZ_DIR=/root/MP-SPDZ nohup ./run_bridge.sh "$SOCK" all 127.0.0.1 127.0.0.1 127.0.0.1 > ../logs/mpc-bridge.log 2>&1 &)
  else
    nohup /root/cairn/cairn mpc-worker --socket-dir "$SOCK" > logs/mpc-worker.log 2>&1 &
  fi
  for _ in $(seq 600); do [ -S "$SOCK/p3.sock" ] && break; sleep 0.5; done
  [ -S "$SOCK/p3.sock" ] || { echo "MPC backend did not start" >&2; exit 1; }
  port=$((BASE + 4))
  for leaf in 2 3 4; do for s in 1 2 3 4; do
    nohup /root/cairn/cairn node --role signer --id "leaf_$leaf/signer_$s" --bind "127.0.0.1:$port" \
      --peers keys/peers.json --group keys/group.bin --tls keys/tls \
      --share "keys/leaf_${leaf}_signer_$s.share" --round-timeout-ms 5000 > "logs/leaf_${leaf}_signer_$s.log" 2>&1 &
    port=$((port + 1))
  done; done
  for k in 1 2 3 4; do
    nohup /root/cairn/cairn node --role root --id "root_$k" --bind "127.0.0.1:$port" \
      --peers keys/peers.json --group keys/group.bin --tls keys/tls \
      --mpc-socket-dir "$SOCK" --mpc-timeout-ms "$MPC_MS" > "logs/root_$k.log" 2>&1 &
    port=$((port + 1))
  done
  nohup /root/cairn/cairn mock-chain --listen "127.0.0.1:$RPC" --chain-id cairn-devnet-1 --height 150 > logs/mock-chain.log 2>&1 &
  sleep 1
  echo "up: $(pgrep -fc '/root/cairn/cairn node') nodes, backend ${2:-reference}";;
*) echo "usage: remote.sh start [reference|mpspdz] | stop" >&2; exit 2;;
esac
