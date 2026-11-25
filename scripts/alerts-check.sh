#!/usr/bin/env bash
# Check deploy/prometheus-alerts.yml three ways:
#   1. promtool validates the rule file;
#   2. promtool runs the unit tests (every alert fires on synthetic series, a healthy
#      committee raises none);
#   3. a real Prometheus scrapes a live local 3-of-4 committee that signs a checkpoint for an
#      unmodified pqc-sidecar: every rule evaluates without error, every metric a rule names
#      exists, and stopping a party is seen.
# Needs prometheus and promtool on PATH, and scripts/setup-verifiers.sh for step 3.
set -euo pipefail
cd "$(dirname "$0")/.."
promtool check rules deploy/prometheus-alerts.yml
promtool test rules deploy/prometheus-alerts.test.yml

SIDECAR="${PQC_SIDECAR_BIN:-$PWD/target/pqc-sidecar/release/pqc-sidecar}"
[ -x "$SIDECAR" ] || { echo "pqc-sidecar binary not found: run scripts/setup-verifiers.sh" >&2; exit 1; }
DIR="$PWD/target/alerts-check" KMS=18210 RPC=18667 BASE=17310 METRICS=19310 PROM=19390
CHAIN=cairn-devnet-1
rm -rf "$DIR" "$DIR.committee.log"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true; pkill -P $$ 2>/dev/null || true' EXIT
scripts/run_local_committee.sh --dir "$DIR" --base-port "$BASE" --kms-port "$KMS" \
  --metrics-base "$METRICS" > "$DIR.committee.log" 2>&1 & PIDS+=($!)
for _ in $(seq 600); do grep -q '^ready$' "$DIR.committee.log" 2>/dev/null && break; sleep 0.2; done
grep -q '^ready$' "$DIR.committee.log" || { cat "$DIR.committee.log"; echo "committee did not start" >&2; exit 1; }
target/release/cairn mock-chain --listen "127.0.0.1:$RPC" --chain-id "$CHAIN" --height 150 2> "$DIR/logs/mock-chain.log" & PIDS+=($!)

mkdir -p "$DIR/sidecar" "$DIR/prom"
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
cat > "$DIR/prom/prometheus.yml" <<YAML
global: { scrape_interval: 1s, evaluation_interval: 1s }
rule_files: ["$PWD/deploy/prometheus-alerts.yml"]
scrape_configs:
  - job_name: cairn-kms
    static_configs: [{ targets: ["127.0.0.1:$METRICS"] }]
  - job_name: cairn-party
    static_configs: [{ targets: ["127.0.0.1:$((METRICS + 1))", "127.0.0.1:$((METRICS + 2))", "127.0.0.1:$((METRICS + 3))", "127.0.0.1:$((METRICS + 4))"] }]
YAML
prometheus --config.file="$DIR/prom/prometheus.yml" --storage.tsdb.path="$DIR/prom/data" \
  --web.listen-address="127.0.0.1:$PROM" --log.level=warn > "$DIR/logs/prometheus.log" 2>&1 & PIDS+=($!)

export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_EC2_METADATA_DISABLED=true
"$SIDECAR" kms-public-key --config "$DIR/sidecar/config.toml" --public-key-out "$DIR/sidecar/public_key.hex" > /dev/null
"$SIDECAR" --config "$DIR/sidecar/config.toml" > "$DIR/logs/pqc-sidecar.log" 2>&1 & PIDS+=($!)
CERT="$DIR/sidecar/certs/00000000000000000100.pqcc"
for _ in $(seq 300); do [ -s "$CERT" ] && break; sleep 0.2; done
[ -s "$CERT" ] || { tail -5 "$DIR/logs/pqc-sidecar.log"; echo "no certificate written" >&2; exit 1; }
# Wait until Prometheus has discovered and scraped all five targets, then a few evaluations.
for _ in $(seq 60); do
  [ "$(curl -fsS "http://127.0.0.1:$PROM/api/v1/query?query=count(up==1)" | grep -o '"5"')" = '"5"' ] && break; sleep 0.5
done
sleep 3

q() { curl -fsS --get "http://127.0.0.1:$PROM/api/v1/query" --data-urlencode "query=$1"; }
PARTY1=$(pgrep -f "node --role party --id party_1 --bind 127.0.0.1:$BASE" | head -1)
python3 - "$PROM" <<'PY'
import json, re, sys, urllib.request, urllib.parse
base = f"http://127.0.0.1:{sys.argv[1]}/api/v1/"
get = lambda path: json.load(urllib.request.urlopen(base + path))["data"]
query = lambda q: get("query?" + urllib.parse.urlencode({"query": q}))["result"]
rules = [r for g in get("rules")["groups"] for r in g["rules"]]
bad = [(r["name"], r.get("lastError")) for r in rules if r["health"] != "ok"]
assert len(rules) == 11 and not bad, f"rules not healthy: {bad}"
targets = get("targets")["activeTargets"]
down = [t["scrapeUrl"] for t in targets if t["health"] != "up"]
assert len(targets) == 5 and not down, f"targets: {[(t["scrapeUrl"], t["health"], t["lastError"]) for t in targets]}"
names = sorted({m for r in rules for m in re.findall(r"cairn_[a-z_]+", r["query"])})
missing = [m for m in names if not query(m)]
assert not missing, f"rules name metrics nobody exports: {missing}"
signed = float(query("cairn_kms_signatures_total")[0]["value"][1])
responded = sum(float(s["value"][1]) for s in query("cairn_party_responses_total"))
assert signed >= 1 and responded >= 3, (signed, responded)
alerts = {a["labels"]["alertname"] for a in get("alerts")["alerts"]}
# Parties have just started, so the restart notice is the one alert expected now.
assert alerts <= {"CairnPartyRestarted"}, f"unexpected alerts on a healthy committee: {alerts}"
print(f"live: 11 rules healthy, 5 targets up, {len(names)} metrics present, "
      f"{signed:.0f} signature(s), {responded:.0f} party responses, alerts: {sorted(alerts)}")
PY
kill "$PARTY1"
for _ in $(seq 40); do
  q 'ALERTS{alertname="CairnPartyDown"}' | grep -q '"alertstate":"pending"' && break; sleep 0.5
done
q 'ALERTS{alertname="CairnPartyDown"}' | grep -q '"alertstate":"pending"' \
  || { echo "stopping a party did not raise CairnPartyDown" >&2; exit 1; }
echo "live: stopping party_1 put CairnPartyDown in pending (it fires after its 5 m hold)"
echo "OK: alert rules validated, unit-tested, and evaluated by Prometheus against a live committee"
