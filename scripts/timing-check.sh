#!/usr/bin/env bash
# Timing measurement of the committee's response round (crates/threshold-mldsa/tests/timing.rs).
#
#   scripts/timing-check.sh [samples]          default 4000, about a minute
#   CAIRN_TIMING_CONTROL=1 scripts/timing-check.sh   both classes get the same share
#
# Times the round for an all-zero share and for a share at the bound, interleaved at random,
# and prints Welch's t for the difference. |t| < 4.5 passes. Run it on a quiet machine: other
# load adds noise, not bias, but a busy machine can hide a small difference.
set -euo pipefail
cd "$(dirname "$0")/.."
CAIRN_TIMING_SAMPLES="${1:-4000}" cargo test --release -p threshold-mldsa --test timing -- --ignored --nocapture 2>&1 \
  | grep -E "data-independent|response round|accepted fraction|test result|panicked|^error"
