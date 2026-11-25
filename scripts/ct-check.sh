#!/usr/bin/env bash
# Machine-code check of the mask sampler's elementary functions (`Dd::ln`, `Dd::cos_sin_turn`
# in crates/threshold-mldsa/src/dd.rs, with the arithmetic they inline):
# compile the crate in release mode for this machine, read the assembly the compiler
# produced, and fail if either function contains a call, or a conditional branch other than
# a fixed-count loop's branch on its integer counter. Their
# inputs decide a secret mask, so their instruction sequence must not depend on the input.
#
# This covers the architecture it runs on, and those two functions only. It says nothing
# about how long a division or a square root takes inside the processor.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=target/ct-check
cargo rustc --quiet -p threshold-mldsa --release --lib --target-dir "$OUT" -- --emit=asm -C debuginfo=0
ASM=$(ls -t "$OUT"/release/deps/threshold_mldsa-*.s | head -1)
python3 - "$ASM" <<'PY'
import re, sys
text = open(sys.argv[1]).read().splitlines()
branch = re.compile(r"^\s*(b\.[a-z]+|cbn?z|tbn?z|j(?!mp)[a-z]+|loop[a-z]*)\b")
call = re.compile(r"^\s*(bl|blr|call[a-z]*)\b")
failed = False
for name in ("ln", "cos_sin_turn"):
    starts = [i for i, l in enumerate(text)
              if re.match(rf"^_?_R\w*threshold_mldsa2dd\w*2Dd{len(name)}{name}:", l)]
    assert len(starts) == 1, f"{name}: expected one compiled copy, found {len(starts)}"
    body = []
    for line in text[starts[0] + 1:]:
        if ".cfi_endproc" in line:
            break
        if re.match(r"^\s+[a-z]", line) and not line.strip().startswith("."):
            body.append(line.strip())
    # A fixed-count loop keeps one branch on its counter. Accept a conditional branch only
    # when the flags it reads were set by an integer instruction with no floating-point
    # operand (the series loops count terms; the quadrant and exponent never reach a compare).
    flags = re.compile(r"^(subs|adds|cmp|cmn|tst|ands|ccmp|fcmp|fcmpe|fccmp|sub|add|dec|inc|test|and|or|xor|u?comis[sd])\b")
    integer = re.compile(r"^(subs|adds|cmp|cmn|tst|ands|sub|add|dec|inc|test)\s+(?!.*\b([dsv]\d+|xmm\d+)\b)")
    bad, counters = [], 0
    for at, l in enumerate(body):
        if call.match(l):
            bad.append(l)
        elif branch.match(l):
            setter = next((p for p in reversed(body[:at]) if flags.match(p)), "")
            if not l.startswith(("cb", "tb")) and integer.match(setter):
                counters += 1
            else:
                bad.append(f"{l}   (flags from: {setter or 'unknown'})")
    print(f"{name}: {len(body)} instructions, {counters} loop-counter branches, "
          f"{len(bad)} other conditional branches or calls")
    for l in bad:
        print("   ", l)
    failed |= bool(bad) or not body
sys.exit(1 if failed else 0)
PY
echo "OK: no input-dependent control flow in the sampler's ln and cos on $(uname -m)"
