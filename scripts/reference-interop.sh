#!/usr/bin/env bash
# Run mixed committees: some parties are cairn (Rust), the rest are the paper authors'
# reference implementation (Go). Needs go and git. Clones the reference at a pinned commit
# into target/, adds one test file to it, and changes nothing else.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=https://github.com/Threshold-ML-DSA/Threshold-ML-DSA
PIN=66e269e75dd8f5d722675a3d276a1aedc58bc4ef
DIR=target/reference-thmldsa
if [ ! -d "$DIR/.git" ]; then
  git clone -q "$REPO" "$DIR"
fi
git -C "$DIR" checkout -q "$PIN"
PKG="$DIR/implementation/sign/thmldsa/thmldsa65/internal"
cp interop/reference/cairn_interop_test.go "$PKG/"
(cd "$PKG" && go vet . >/dev/null)
CAIRN_REFERENCE_PKG="$(cd "$PKG" && pwd)" \
  cargo test -p threshold-mldsa --release reference_interop -- --ignored --nocapture
