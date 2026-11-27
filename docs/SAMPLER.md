# The mask sampler: how close to exact, and how constant in time

A party's mask is a uniform point in a hyperball, rounded to integers. The scheme's security
proof is about that distribution. This note says what cairn computes, how far it is from the
ideal, how that was measured, and what is still not established. It concerns
[BLOCKERS.md](BLOCKERS.md) items 2 and 3.

## What is computed

`crates/threshold-mldsa/src/mithril.rs` (`ball_from_uniforms`) and `dd.rs`:

1. 1409 pairs of uniforms: `u1` with 105 random bits, `u2` with 106.
2. Two Gaussians per pair by Box-Muller: `sqrt(-2 ln u1)` times `cos(2 pi u2)` and
   `sin(2 pi u2)`.
3. Divide by the norm of all 2818, drop two, scale by the radius: a uniform point in the
   2816-dimensional ball. This is the method of the paper and of the authors' reference
   implementation.
4. Round each coordinate to an integer (the first 1280 after multiplying by nu = 6).

The reference does steps 1 to 4 in `float64` with the Go library's `Log` and `Cos`. cairn did
the same until v0.4.0. It now does them in double-double arithmetic (two doubles per value,
about 106 bits) with its own `ln` and `cos`, and the rejection test in round 3 sums in
double-double too.

## How far from the formula

`sampler_precision` tests run the same uniforms through the sampler and through a 256-bit
evaluation of the same formula (the `astro-float` crate, tests only).

| | largest error in a coordinate before rounding | coordinates rounded differently |
|---|---|---|
| `f64`, system `ln`/`cos` (through v0.4.0) | 6.4e-10 over 2,816,000 coordinates | 0 |
| double-double (now) | 1.2e-26 over 5,632 coordinates in the default run | 0 |

`ln`, `cos`, `sqrt` and division are each within 4e-32 of the 256-bit value over 6,500 inputs
including the ends of their ranges. Run more samples with
`CAIRN_SAMPLER_SAMPLES=1000 cargo test -p threshold-mldsa --release sampler_matches`.

## How far from the ideal distribution: an estimate, not a proof

Take ideal real-valued uniforms, and the sampler's uniforms as their truncation to the
grid. Both go through the same formula; the outputs differ only if some coordinate lands
close enough to a half-integer for the difference to change its rounding. Counting how often
that can happen bounds the statistical distance between the sampler's masks and ideal ones.
Two sources:

- **Arithmetic.** An error of e in a coordinate changes its rounding with probability about
  2e. With the measured errors, per mask of 2816 coordinates: about 4e-6 for `f64`, about
  7e-23 for double-double.
- **Uniforms on a grid.** Perturbing `u1` by one grid step moves the Gaussian by
  `step / (u1 sqrt(-2 ln u1))`, which averages to about 12 steps; the grid of `u2` and the
  shared norm contribute terms of the same order, which the estimate covers only because it
  counts a full step where the mean offset is a quarter of one. Per mask: about 1e-7 with
  53-bit uniforms, about 3e-23 with these (`u1` has 105 bits, not 106: its low word must be
  exact in a double).

So the estimate is a distance of about **2^-18 per mask before, 2^-73 per mask now**. A
signature uses as many masks per party and attempt as the committee has repetitions: 5 for
2-of-3, 20 for 3-of-4, and up to 1200 for 5-of-6. So per attempt and party the distance is
about 2^-71 at 2-of-3 and about 2^-63 at 5-of-6.

What this estimate is not:

- It assumes the fractional part of a coordinate is spread evenly, which is plausible (a
  coordinate ranges over tens of thousands) and unproven.
- The arithmetic error is measured on samples, not bounded for all inputs.
- It is a statistical distance. Whether the paper's proof can absorb 2^-73 per mask, and with
  what loss, is a question about that proof which has not been worked through here.
- 2^-73 per mask is small, not negligible in the 2^-128 sense. Going further needs wider
  arithmetic (the 256-bit path used in the tests is about a thousand times slower) or an
  integer sampler with a proof of its own.

## Timing

The inputs to the sampler decide the mask, and a mask together with the published response
gives the party's share. So the sampler must not take input-dependent paths.

- **Done.** `ln` and `cos` are fixed sequences of additions, multiplications, divisions and
  square roots: no table lookup, no library call, no fused multiply-add (a library call on
  processors without the instruction), and the quadrant and exponent are applied by
  arithmetic. Rounding uses additions only. `scripts/ct-check.sh` compiles the crate and
  reads the generated assembly of both functions: on arm64 they contain no call and no
  conditional branch except one fixed-count loop counter each.
- **Not established.** The check covers arm64 and those two functions. Division and square
  root instructions can take data-dependent time inside some processors. The polynomial
  arithmetic around the sampler is branch-free at source level (see item 3) but its machine
  code has not been read.
- **Measured, and one leak found and closed (2026-11-27).** `scripts/timing-check.sh` times
  the response round for an all-zero share and for a share with every coefficient at the
  bound, interleaved at random, 4,000 samples, and compares the means (Welch's t; below 4.5
  passes). On an Apple M3 the round was about 5 of 705 microseconds faster for the zero
  share: t between 3 and 31 over four runs, and 0.4 to 0.6 in control runs that gave both
  classes the same share. The source has no branch on the share, so the processor itself was
  taking data-dependent time. With the processor's data-independent-timing bit set (arm64
  DIT) the difference went away: t of 0.3 to 1.6 over four runs. Every thread that samples a
  mask or computes a response now sets that bit first (`threshold_mldsa::ct`), at a cost of
  about 5% of the round. Limits: one processor; one committee size (2-of-3); a
  statistical test finds differences, it does not prove there are none; and on x86-64 the
  equivalent setting (DOITM) belongs to the operating system, so cairn cannot turn it on there.
- **The mask round, measured (2026-11-27).** The same script times round 1, which samples
  the masks, for the same randomness every time against fresh randomness each time: t of
  0.7, -0.6, -0.1 and -1.8 over four runs of 4,000 samples, and -0.2 and -1.2 in control
  runs. No difference found. The machine was also running a long signing test at the time,
  which adds noise and could hide a small difference.
- **Share files, not measured.** Reading and writing a share file take 8 and 4 microseconds.
  An attempt to time them for the two share classes showed differences of under 0.1
  microseconds with t above 4.5, but so did the control runs with identical data, so the
  method cannot tell data from memory layout at that scale and the test was not kept. A
  share file is read once when a party starts, on its own machine.
- **Erasure.** Shares, masks, the uniforms behind them, rejected responses and share file
  buffers are overwritten when dropped. A rejected response is computed and then erased,
  so the work done does not depend on whether a repetition is accepted.
- **Key generation.** Secrets are expanded with the FIPS 204 rejection sampler (`ExpandS`),
  whose running time depends on how many candidates are rejected, as in every implementation
  of the standard. That is unchanged.

## Interoperation with the reference

Each party samples its own masks, so parties with different samplers sign together as long
as each one's masks are in the ball. `scripts/reference-interop.sh` still passes: mixed
committees of the authors' Go code and cairn produce signatures both sides accept.
