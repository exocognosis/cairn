#!/usr/bin/env bash
# Two-host run of a flat committee (three-round protocol): party_1 and the coordinator on this
# machine, the other parties on a remote host, reached through SSH port forwards so that no
# port is opened there. Prints one benchmark row.
#
#   scripts/split-host/committee.sh <user@host> <T-of-N> [signatures]
#   KEEP=1 scripts/split-host/committee.sh <user@host> <T-of-N>     (keep it running instead)
#
# Needs target/release/cairn here and the Linux build at
# target/x86_64-unknown-linux-gnu/release/cairn (cargo zigbuild).
set -euo pipefail
cd "$(dirname "$0")/../.."
HOST="${1:?user@host}" SPEC="${2:?T-of-N}" COUNT="${3:-50}"
N="${SPEC##*-of-}" BASE="${BASE:-17300}" DIR=target/split-committee
CAIRN="$PWD/target/release/cairn"
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
cleanup() {
  pkill -f "cairn-committee-forward" 2>/dev/null || true
  pkill -f "$CAIRN node --role party" 2>/dev/null || true
  $SSH "$HOST" 'pkill -f "/root/cairn/cairn node" || true' 2>/dev/null || true
}
trap cleanup EXIT
cleanup
rm -rf "$DIR" && mkdir -p "$DIR/logs"
"$CAIRN" keygen --out "$DIR/keys" --committee "$SPEC" --base-port "$BASE" > /dev/null
$SSH "$HOST" 'rm -rf /root/cairn/ckeys && mkdir -p /root/cairn/ckeys/tls /root/cairn/logs'
scp -q target/x86_64-unknown-linux-gnu/release/cairn "$HOST:/root/cairn/cairn"
REMOTE_SHARES=() REMOTE_TLS=("$DIR/keys/tls/fingerprints.json")
for k in $(seq 2 "$N"); do
  REMOTE_SHARES+=("$DIR/keys/party_$k.share")
  REMOTE_TLS+=("$DIR/keys/tls/party_$k.pem" "$DIR/keys/tls/party_$k.key")
done
scp -q "$DIR/keys/committee.bin" "$DIR/keys/peers.json" "${REMOTE_SHARES[@]}" "$HOST:/root/cairn/ckeys/"
scp -q "${REMOTE_TLS[@]}" "$HOST:/root/cairn/ckeys/tls/"
FWD=()
for k in $(seq 2 "$N"); do
  port=$((BASE + k - 1)); FWD+=(-L "$port:127.0.0.1:$port")
  # setsid -f detaches the node so the SSH session can close.
  $SSH "$HOST" "cd /root/cairn && setsid -f /root/cairn/cairn node --role party --id party_$k --bind 127.0.0.1:$port \
    --peers ckeys/peers.json --committee ckeys/committee.bin --tls ckeys/tls --share ckeys/party_$k.share \
    > logs/party_$k.log 2>&1 < /dev/null"
done
ssh -f -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 \
  -o SetEnv=TAG=cairn-committee-forward "${FWD[@]}" "$HOST"
nohup "$CAIRN" node --role party --id party_1 --bind "127.0.0.1:$BASE" --peers "$DIR/keys/peers.json" \
  --committee "$DIR/keys/committee.bin" --tls "$DIR/keys/tls" --share "$DIR/keys/party_1.share" \
  > "$DIR/logs/party_1.log" 2>&1 &
for p in $(seq "$BASE" $((BASE + N - 1))); do
  for _ in $(seq 100); do nc -z 127.0.0.1 "$p" 2>/dev/null && break; sleep 0.1; done
done
sleep 1
if [ -n "${KEEP:-}" ]; then
  # Leave the committee running until target/split-committee/stop appears (for a sidecar run).
  echo ready > "$DIR/ready"
  while [ ! -e "$DIR/stop" ]; do sleep 0.5; done
  exit 0
fi
"$CAIRN" remote-bench --peers "$DIR/keys/peers.json" --committee "$DIR/keys/committee.bin" \
  --tls "$DIR/keys/tls" --signatures "$COUNT"
