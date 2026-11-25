#!/usr/bin/env bash
# Rehearse a rolling upgrade on this machine: a 3-of-4 committee generates its key and signs
# with the OLD release, then every party and finally the coordinator is replaced by the NEW
# binary, one at a time, on the same files. An unmodified pqc-sidecar keeps asking for
# checkpoints throughout and must get a certificate after every step, and all certificates
# must verify under the one key generated at the start.
#
#   scripts/upgrade-rehearsal.sh [--from v0.3.0] [--old <binary>] [--new <binary>]
#
# OLD defaults to the published release archive for this platform (downloaded with gh and
# checked against its SHA-256); NEW defaults to this checkout's release build.
# Needs scripts/setup-verifiers.sh to have been run (or PQC_SIDECAR_BIN set).
set -euo pipefail
cd "$(dirname "$0")/.."
FROM=v0.3.0 OLD="" NEW=""
while [ $# -gt 0 ]; do
  case "$1" in --from) FROM="$2";; --old) OLD="$2";; --new) NEW="$2";; *) echo "unknown option $1" >&2; exit 2;; esac
  shift 2
done
SIDECAR="${PQC_SIDECAR_BIN:-$PWD/target/pqc-sidecar/release/pqc-sidecar}"
[ -x "$SIDECAR" ] || { echo "pqc-sidecar binary not found: run scripts/setup-verifiers.sh" >&2; exit 1; }
DIR="$PWD/target/upgrade-rehearsal" KMS=18220 RPC=18677 BASE=17320 CHAIN=cairn-devnet-1 N=4
rm -rf "$DIR" && mkdir -p "$DIR/logs" "$DIR/old" "$DIR/sidecar"
if [ -z "$NEW" ]; then cargo build --quiet --release -p cairn-sidecar; NEW="$PWD/target/release/cairn"; fi
if [ -z "$OLD" ]; then
  case "$(uname -sm)" in
    "Darwin arm64") TRIPLE=aarch64-apple-darwin;; "Linux x86_64") TRIPLE=x86_64-unknown-linux-gnu;;
    "Linux aarch64") TRIPLE=aarch64-unknown-linux-gnu;; *) echo "no release archive for $(uname -sm); pass --old" >&2; exit 1;;
  esac
  gh release download "$FROM" --repo exocognosis/cairn -p "*$TRIPLE*" -D "$DIR/old"
  (cd "$DIR/old" && shasum -a 256 -c ./*.sha256 > /dev/null && tar xzf ./*.tar.gz)
  OLD="$(find "$DIR/old" -type f -name cairn | head -1)"
fi
echo "old: $OLD"; echo "new: $NEW"

PIDS=() MOCK="" COORD=""
PARTY=(0 0 0 0 0)
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
port() { for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never opened" >&2; exit 1; }
party() { # party <binary> <k>
  "$1" node --role party --id "party_$2" --bind "127.0.0.1:$((BASE + $2 - 1))" \
    --peers "$DIR/keys/peers.json" --committee "$DIR/keys/party_$2/committee.bin" --tls "$DIR/keys/tls" \
    --share "$DIR/keys/party_$2/party_$2.share" --state "$DIR/party_$2.state.json" \
    --audit-log "$DIR/logs/party_$2.audit.log" 2>> "$DIR/logs/party_$2.log" &
  PARTY[$2]=$!; PIDS+=($!); port "$((BASE + $2 - 1))"
}
coordinator() { # coordinator <binary>
  "$1" serve-kms --listen "127.0.0.1:$KMS" --peers "$DIR/keys/peers.json" \
    --committee "$DIR/keys/party_1/committee.bin" --tls "$DIR/keys/tls" 2>> "$DIR/logs/serve-kms.log" &
  COORD=$!; PIDS+=($!); port "$KMS"
}
HEIGHT=100
next_certificate() { # the chain advances one checkpoint; the sidecar must certify it
  HEIGHT=$((HEIGHT + 100))
  [ -n "$MOCK" ] && { kill "$MOCK"; wait "$MOCK" 2>/dev/null || true; }
  "$NEW" mock-chain --listen "127.0.0.1:$RPC" --chain-id "$CHAIN" --height "$((HEIGHT + 50))" 2>> "$DIR/logs/mock-chain.log" &
  MOCK=$!; PIDS+=($!)
  local cert; cert="$DIR/sidecar/certs/$(printf '%020d' "$HEIGHT").pqcc"
  for _ in $(seq 300); do [ -s "$cert" ] && break; sleep 0.2; done
  [ -s "$cert" ] || { tail -5 "$DIR/logs/pqc-sidecar.log"; echo "no certificate at height $HEIGHT after: $1" >&2; exit 1; }
  "$SIDECAR" verify --certificate "$cert" --public-key "$DIR/sidecar/public_key.hex" > /dev/null
  echo "height $HEIGHT certified and verified after: $1"
}

# Everything the committee owns is made by the old release.
"$OLD" committee-init --out "$DIR/keys" --committee "3-of-$N" --base-port "$BASE" > "$DIR/init.json"
DKG=()
for k in $(seq $N); do
  "$OLD" dkg-party --id "party_$k" --bind "127.0.0.1:$((BASE + k - 1))" --roster "$DIR/keys/roster.json" \
    --identity "$DIR/keys/party_$k/identity.pk8" --tls "$DIR/keys/tls" --out "$DIR/keys/party_$k" \
    2> "$DIR/logs/dkg_party_$k.log" & DKG+=($!)
done
for k in $(seq $N); do port "$((BASE + k - 1))"; done
"$OLD" dkg --roster "$DIR/keys/roster.json" --peers "$DIR/keys/peers.json" --tls "$DIR/keys/tls" > "$DIR/dkg.json"
wait "${DKG[@]}"
for k in $(seq $N); do party "$OLD" "$k"; done
coordinator "$OLD"

cat > "$DIR/sidecar/config.toml" <<TOML
[signer]
backend = "aws_kms"
aws_kms_key_id = "alias/cairn-tower"
aws_region = "us-east-1"
aws_endpoint_url = "http://127.0.0.1:$KMS"
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
HEIGHT=0
"$NEW" mock-chain --listen "127.0.0.1:$RPC" --chain-id "$CHAIN" --height 150 2>> "$DIR/logs/mock-chain.log" & MOCK=$!; PIDS+=($!)
port "$RPC"
"$SIDECAR" --config "$DIR/sidecar/config.toml" > "$DIR/logs/pqc-sidecar.log" 2>&1 & PIDS+=($!)
next_certificate "everything on the old release"

for k in $(seq $N); do
  kill "${PARTY[$k]}"; wait "${PARTY[$k]}" 2>/dev/null || true
  party "$NEW" "$k"
  next_certificate "party_$k upgraded ($k of $N new, coordinator old)"
done
kill "$COORD"; wait "$COORD" 2>/dev/null || true
coordinator "$NEW"
next_certificate "coordinator upgraded (everything new)"
echo "OK: rolling upgrade kept signing under one key; $(ls "$DIR/sidecar/certs" | wc -l | tr -d ' ') certificates verified"
