#!/usr/bin/env bash
# Fetch/build the unmodified external verifiers the end-to-end test runs against.
#   PQC_SIDECAR_DIR  pqc-sidecar checkout (default: ../pqc-sidecar). Built as is, into
#                    target/pqc-sidecar; nothing is written to the checkout.
set -euo pipefail
cd "$(dirname "$0")/.."
SIDECAR="${PQC_SIDECAR_DIR:-../pqc-sidecar}"
cargo build --release --locked --manifest-path "$SIDECAR/Cargo.toml" --target-dir target/pqc-sidecar
mkdir -p target/pqcc-verify
npm install --silent --no-audit --no-fund --prefix target/pqcc-verify @exocognosis/pqc-sidecar-verify
echo "pqc-sidecar:        $(git -C "$SIDECAR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "pqc-sidecar-verify: $(node -p "require('./target/pqcc-verify/node_modules/@exocognosis/pqc-sidecar-verify/package.json').version")"
