#!/usr/bin/env bash
# Coverage-guided fuzzing of every parser of outside bytes (fuzz/fuzz_targets).
# Needs: rustup toolchain install nightly; cargo install cargo-fuzz.
#
#   scripts/fuzz.sh [seconds per target]      default 300
#
# Starts each target from valid inputs written by the test suite. A crash stops the script and
# leaves the input under fuzz/artifacts/.
set -euo pipefail
cd "$(dirname "$0")/.."
seconds="${1:-300}"
CAIRN_FUZZ_SEEDS="$PWD/fuzz/corpus" cargo test -q -p cairn-sidecar --test hostile_input write_fuzz_seeds -- --ignored >/dev/null
for target in keys frame text; do
  echo "== $target, $seconds s"
  cargo +nightly fuzz run "$target" -- -max_total_time="$seconds" -max_len=65536 -print_final_stats=1 2>&1 \
    | grep -E "^stat::number_of_executed_units|cov: [0-9]+ .*DONE|ERROR|SUMMARY|panicked|Test unit written" || true
  if ls fuzz/artifacts/"$target"/* >/dev/null 2>&1; then
    echo "crash input(s) in fuzz/artifacts/$target"; exit 1
  fi
done
