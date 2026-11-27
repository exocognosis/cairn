#!/usr/bin/env python3
"""Summarize an MP-SPDZ bridge log (logs/mpc-bridge.log from remote.sh start mpspdz).

    mpc-phases.py <mpc-bridge.log>

Prints one Markdown row per phase: runs, bridge wall time, time inside MP-SPDZ, data sent per
party and rounds, each as the mean over every party's run of that phase, and the failure count.
"""
import re
import sys

LINE = re.compile(
    r"\[bridge p(\d)\] (mask|response): exit (-?\d+), ([\d.]+) s wall; "
    r"Time = ([\d.]+) seconds; Data sent = ([\d.]+) MB in ~(\d+) rounds"
)


def main(path):
    rows, failed = {}, {}
    for line in open(path, errors="replace"):
        m = LINE.search(line)
        if m:
            _, phase, code, wall, inside, mb, rounds = m.groups()
            if code != "0":
                failed[phase] = failed.get(phase, 0) + 1
            rows.setdefault(phase, []).append((float(wall), float(inside), float(mb), int(rounds)))
        elif re.search(r"\] (mask|response): exit -?[1-9]", line):
            phase = re.search(r"\] (mask|response):", line).group(1)
            failed[phase] = failed.get(phase, 0) + 1
    print("| phase | attempts | wall s | inside MP-SPDZ s | MB sent per party | rounds | failed runs |")
    print("|---|---|---|---|---|---|---|")
    for phase in ("mask", "response"):
        r = rows.get(phase, [])
        if not r:
            continue
        mean = lambda i: sum(x[i] for x in r) / len(r)
        print(
            "| %s | %d | %.2f | %.2f | %.1f | %.0f | %d |"
            % (phase, len(r) // 3, mean(0), mean(1), mean(2), mean(3), failed.get(phase, 0))
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
