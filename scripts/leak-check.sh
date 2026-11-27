#!/usr/bin/env bash
# Statistical test of the published responses (crates/threshold-mldsa/tests/leak.rs): does
# `z = c s + r`, as published after rejection, lean towards `c s`?
#
#   scripts/leak-check.sh [samples]     default 100000 signing attempts, about ten minutes
set -euo pipefail
cd "$(dirname "$0")/.."
CAIRN_LEAK_SAMPLES="${1:-100000}" cargo test --release -p threshold-mldsa --test leak -- --ignored --nocapture 2>&1 \
  | grep -E "share|test result|panicked|^error"
