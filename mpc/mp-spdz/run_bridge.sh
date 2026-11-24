#!/usr/bin/env bash
# Compile mldsa65_root_attempt and launch the cairn MP-SPDZ bridge.
#
#   MPSPDZ_DIR=/path/to/MP-SPDZ ./run_bridge.sh <socket-dir> <party|all> <host1> <host2> <host3>
#
# <party> is 1, 2 or 3 (this host's party), or `all` to run the three bridges on one machine.
# Environment:
#   MPSPDZ_DIR   MP-SPDZ checkout with compile.py and the built party binary     (required)
#   WORK_DIR     build output and per-session state      (default: <socket-dir>/work)
#   PROTOCOL     replicated-field | malicious-rep-field   (default: replicated-field)
#   PORT_BASE    first TCP port for the MPC parties; 6000 ports are used (default: 14000)
#   SSL_DIR      directory with P0.pem P1.pem P2.pem, this party's P<k-1>.key and the
#                c_rehash links (as written by MP-SPDZ Scripts/setup-ssl.sh 3)
#                With <party> = all and no SSL_DIR, throwaway certificates are generated.
#   OPENSSL      openssl binary for those certificates; use the version MP-SPDZ links against
#   UNENCRYPTED  1: no TLS between the MPC parties; needs MP-SPDZ built with -DINSECURE
#   PARTY_ARGS   extra arguments for the party binary, space separated (e.g. "-S 20")
#   TIMEOUT      seconds per phase                        (default: 900)
set -euo pipefail

if [ $# -ne 5 ] || [ -z "${MPSPDZ_DIR:-}" ]; then
    sed -n '2,18p' "$0" >&2
    exit 2
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$1"
SOCKET_DIR="$(cd "$1" && pwd)"
PARTY="$2"
HOSTS="$3,$4,$5"
MPSPDZ_DIR="$(cd "$MPSPDZ_DIR" && pwd)"
WORK_DIR="${WORK_DIR:-$SOCKET_DIR/work}"
PROTOCOL="${PROTOCOL:-replicated-field}"
BUILD="$WORK_DIR/build"

[ -x "$MPSPDZ_DIR/$PROTOCOL-party.x" ] || {
    echo "missing $MPSPDZ_DIR/$PROTOCOL-party.x (run: make -C \$MPSPDZ_DIR $PROTOCOL-party.x)" >&2
    exit 1
}

# Compile in a private Programs/ tree, so nothing is written into the MP-SPDZ checkout.
mkdir -p "$BUILD/Programs/Source"
if ! cmp -s "$HERE/mldsa65_root_attempt.mpc" "$BUILD/Programs/Source/mldsa65_root_attempt.mpc" \
    || [ ! -f "$BUILD/Programs/Schedules/mldsa65_root_attempt-mask.sch" ] \
    || [ ! -f "$BUILD/Programs/Schedules/mldsa65_root_attempt-response.sch" ]; then
    cp "$HERE/mldsa65_root_attempt.mpc" "$BUILD/Programs/Source/"
    for phase in mask response; do
        (cd "$BUILD" && python3 "$MPSPDZ_DIR/compile.py" -P 8380417 mldsa65_root_attempt "$phase" \
            > "compile-$phase.log" 2>&1) || { tail -n 30 "$BUILD/compile-$phase.log" >&2; exit 1; }
    done
fi

ARGS=(--socket-dir "$SOCKET_DIR" --mpspdz-dir "$MPSPDZ_DIR" --program-dir "$BUILD/Programs"
      --work-dir "$WORK_DIR/run" --hosts "$HOSTS" --protocol "$PROTOCOL"
      --port-base "${PORT_BASE:-14000}" --timeout "${TIMEOUT:-900}")
for a in ${PARTY_ARGS:-}; do
    ARGS+=("--party-arg=$a")
done
if [ "${UNENCRYPTED:-0}" = 1 ]; then
    ARGS+=(--unencrypted)
elif [ -n "${SSL_DIR:-}" ]; then
    ARGS+=(--ssl-dir "$SSL_DIR")
elif [ "$PARTY" = all ]; then
    # One machine: throwaway self-signed certificates, as Scripts/setup-ssl.sh makes them.
    SSL_DIR="$WORK_DIR/ssl"
    if [ ! -f "$SSL_DIR/P2.pem" ]; then
        mkdir -p "$SSL_DIR"
        for i in 0 1 2; do
            "${OPENSSL:-openssl}" req -newkey rsa:2048 -nodes -x509 -days 30 -subj "/CN=P$i" \
                -addext "subjectAltName=DNS:P$i" \
                -out "$SSL_DIR/P$i.pem" -keyout "$SSL_DIR/P$i.key" 2>/dev/null
            ln -sf "P$i.pem" "$SSL_DIR/$("${OPENSSL:-openssl}" x509 -hash -noout -in "$SSL_DIR/P$i.pem").0"
        done
    fi
    ARGS+=(--ssl-dir "$SSL_DIR")
else
    echo "set SSL_DIR (certificates shared by the three hosts)" >&2
    exit 2
fi

if [ "$PARTY" = all ]; then
    pids=()
    trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT INT TERM
    for p in 1 2 3; do
        python3 "$HERE/bridge.py" --party "$p" "${ARGS[@]}" &
        pids+=($!)
    done
    wait
else
    exec python3 "$HERE/bridge.py" --party "$PARTY" "${ARGS[@]}"
fi
