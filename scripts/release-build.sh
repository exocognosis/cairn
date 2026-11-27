#!/bin/sh
# Build the release binary so that the same commit gives the same bytes wherever the
# checkout and the build directory are. See docs/RELEASING.md.
#   scripts/release-build.sh [extra cargo arguments, such as --target <triple>]
set -eu
cd "$(dirname "$0")/.."
home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$home=/cargo --remap-path-prefix=$rustup_home=/rustup"
export RUSTFLAGS
cargo build --release --locked -p cairn-sidecar "$@"
dir="${CARGO_TARGET_DIR:-target}"
prev=""
for arg in "$@"; do
    if [ "$prev" = "--target" ]; then dir="$dir/$arg"; fi
    prev="$arg"
done
if command -v shasum >/dev/null; then shasum -a 256 "$dir/release/cairn"; else sha256sum "$dir/release/cairn"; fi
