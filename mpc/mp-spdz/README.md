# MP-SPDZ backend for the cairn root engines

The non-linear half of one threshold ML-DSA-65 signing attempt, run as a 3-party
honest-majority MPC over the prime field Z_q, q = 8380417, behind the cairn IPC wire protocol
(`crates/mpc-bridge`).

| File | What it is |
| --- | --- |
| `mldsa65_root_attempt.mpc` | MP-SPDZ program, two phases: `mask` and `response` |
| `bridge.py` | one process per party: `p<k>.sock` <-> one MP-SPDZ party (Python 3 stdlib only) |
| `run_bridge.sh` | compiles the program and launches the bridge(s) |
| `local_test.py` | client that checks a running backend against FIPS 204 computed in Python |

## Protocol choice

- `replicated-field-party.x -P 8380417` (semi-honest, 3 parties, replicated secret sharing mod
  q). This is the default and the configuration that was tested.
- `replicated-ring-party.x` does **not** fit: it computes in Z_2^k. Every share here (seed,
  mask, response) is additive mod q, and A y, HighBits/LowBits and the norm checks are
  arithmetic mod q. Use a `*-field-party.x` binary with `-P 8380417`, never a ring one.
- `malicious-rep-field-party.x` runs the same bytecode, but stock MP-SPDZ refuses a 23-bit
  field at its default 40-bit statistical security ("Field too small (23 bits) for chosen
  security (40)"). It runs with `PARTY_ARGS="-S 20"`, which gives only about 20 bits of
  statistical security for the multiplication check: fine for a functional test, not a
  production setting. Malicious security at full strength needs a check over an extension
  field (as the lattice-aggregation prototype's malicious ATLAS does); that is not part of
  this directory.

Everything is in the arithmetic domain, with no edaBits/daBits: a bit is a field element in
{0, 1}; bit decomposition is exact (Nishide-Ohta, as MP-SPDZ `BitDecFull`); SHAKE256 is an
arithmetic Keccak. The helper section of the program comes from the prototype
`mldsa65_sign_attempt.mpc`.

## What the two phases compute

`mask` (all three parties, same session, attempt, mu, rho):
K = sum of the three `k_share` vectors (each sum must be below 256, else FAULT 2);
rho'' = SHAKE256(K || 0^32 || mu, 64); y = ExpandMask(rho'', 5 * attempt) exactly as FIPS 204
Algorithm 34 (five SHAKE256 instances side by side in one interleaved Keccak state);
w = A y with A = ExpandA(rho); c~ = SHAKE256(mu || w1Encode(HighBits(w)), 48).
Opened: c~. Each party privately receives a fresh additive share of y. w stays secret-shared,
stored through MP-SPDZ persistence for the next phase.

`response`: c = SampleInBall(c~) is public. For each party k the difference
A z_k - r_k - c T_k is opened; it is zero for an honest party, and the lowest k with a nonzero
one is blamed (FAULT 1). Then z = sum z_k, r = sum r_k, and on shares:
||r - w||_inf <= 196 (opened; FAULT 2 if false), ||z||_inf < 2^19 - 196,
||LowBits(r)||_inf < 261888 - 196, ||c t0||_inf < 261888 (public),
h = MakeHint(-c t0, r + c t0) with weight <= 55. Only the accept bit is opened; on accept,
also h and z_1, z_2, z_3.

Other openings: a 32-byte digest per party of the public context (session, attempt, mu, rho;
then session, c~, t0, T), compared first so that parties disagreeing on a public value stop
with FAULT 3; the validity bits of fresh random masks; the uniformly masked values of the bit
decompositions; the bit "all K sums are bytes". The docstring of the `.mpc` file has the list.

Public values derived from the request (A-hat, c T_k, c t0, the nonce bits) are computed by
each bridge and given to its party as MP-SPDZ public input.

## Wire protocol

One Unix socket per party (`p1.sock`, `p2.sock`, `p3.sock`). Frame: u32 big-endian length,
payload; payload[0] is the tag; other integers little-endian; field elements u32 LE in [0, q);
polynomial vectors row-major, 256 coefficients per polynomial. One request and one reply per
frame; a connection may carry several.

| Tag | Message | Body |
| --- | --- | --- |
| 0x01 | MASK | session[32], party u8 (1..3), attempt u32, mu[64], rho[32], k_share[32 x u32] |
| 0x02 | RESPONSE | session[32], party u8, z_share[1280], r_share[1536], t0[1536], T[3 x 1536] |
| 0x03 | CLOSE | session[32] |
| 0x81 | MASK_OK | c_tilde[48], y_share[1280 x u32] |
| 0x82 | REJECT | |
| 0x83 | ACCEPT | n u16, n x u16 hint positions (i*256+j, ascending), z_1[1280], z_2, z_3 |
| 0x84 | CLOSED | |
| 0x8F | FAULT | code u8 (1 blame, 2 unattributed, 3 protocol), party u8, msg_len u16, utf8 |

Bridge-level faults: malformed request, wrong party number, element >= q, attempt too large
for a u16 kappa, timeout: code 3. RESPONSE without a pending MASK for the session (w is
single-use), or an MPC run that ends without a verdict: code 2.

## Commands

Build the party binary once (about 3 minutes here):

    make -C $MPSPDZ_DIR -j8 replicated-field-party.x

One machine, three bridges (compiles the program on first use, generates throwaway TLS
certificates for the parties):

    MPSPDZ_DIR=/path/to/MP-SPDZ ./run_bridge.sh /tmp/cmq all 127.0.0.1 127.0.0.1 127.0.0.1
    python3 local_test.py /tmp/cmq
    CAIRN_MPC_SOCKET_DIR=/tmp/cmq cargo test -p mpc-bridge      # from the cairn root

Three hosts (party k on host k; same `PORT_BASE` and same certificates everywhere):

    MPSPDZ_DIR=... SSL_DIR=/etc/cairn/mpc-ssl ./run_bridge.sh /run/cairn/mpc <k> host1 host2 host3

`SSL_DIR` holds `P0.pem P1.pem P2.pem`, this party's `P<k-1>.key` and the `c_rehash` hash
links (MP-SPDZ `Scripts/setup-ssl.sh 3 <dir>`, then copy the `.pem` files to every host).
Other variables: `WORK_DIR`, `PROTOCOL`, `PORT_BASE` (default 14000), `PARTY_ARGS`, `TIMEOUT`,
`OPENSSL`; see the head of `run_bridge.sh`. By hand, the compile step is

    compile.py -P 8380417 mldsa65_root_attempt mask
    compile.py -P 8380417 mldsa65_root_attempt response

run from a directory whose `Programs/Source/` holds the `.mpc` file.

Notes from getting it to run:

- Keep the socket directory path short: Unix socket paths are limited to about 104 bytes.
- The MP-SPDZ build here links OpenSSL 4, which rejected party certificates without a
  subjectAltName; `run_bridge.sh` adds `subjectAltName=DNS:P<i>` and takes the `openssl` binary
  from `OPENSSL`. LibreSSL's `openssl` (macOS default) did not produce usable certificates.
- `UNENCRYPTED=1` passes `-u`, which MP-SPDZ only accepts when built with `-DINSECURE`.
- The bridge sets `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH` to `MPSPDZ_DIR` (for `libSPDZ.so`) and
  runs the party with `-OF .` so that every party, not only party 0, prints the openings.

## Sessions and state

Each session gets its own directory under `WORK_DIR/run/p<k>/` (inputs, private output,
`Persistence/` with this party's shares of w) and a TCP port triple derived from the session
id inside `[PORT_BASE, PORT_BASE + 6000)`, so different sessions can run at the same time. Two
live sessions land on the same ports with probability 1/2000; the run then fails with a FAULT
and can be retried. The private input file is deleted after each run, the private output
after it is read, the persistence file after RESPONSE, the directory on CLOSE. A bridge whose
peers never start the same phase waits until `TIMEOUT`.

## Measured

Apple silicon laptop, three parties on localhost over TLS, MP-SPDZ at commit 6a2256e,
per attempt, per party (MP-SPDZ's own counters):

| Protocol | Phase | Time | Data sent per party | Rounds |
| --- | --- | --- | --- | --- |
| replicated-field | mask | 1.2 s (1.8 s with process start) | 85.1 MB | ~1943 |
| replicated-field | response | 0.33 s (0.7 s) | 15.6 MB | ~91 |
| malicious-rep-field, `-S 20` | mask | 5.2 s (5.8 s) | 425 MB | ~7281 |
| malicious-rep-field, `-S 20` | response | 0.96 s (1.3 s) | 76 MB | ~1071 |

Compiler counts: mask 10,599,327 multiplications, response 1,791,469. These are loopback
numbers; with ~1900 rounds the mask phase is latency-bound on a real network (untested).

## Verification status

- Compiles with compile.py -P 8380417, both phases (yes).
- Ran 3 parties locally with replicated-field-party.x over TLS through bridge.py (yes).
- Matched the reference (yes): `local_test.py` passed (c~, the sum of the y shares, REJECT and
  ACCEPT verdicts, hint positions and opened z_k equal to an independent Python computation
  of the FIPS 204 semantics; FAULT 1 naming party 2, FAULT 2 for a shifted mask share, a
  stale RESPONSE and non-byte seed sums, FAULT 3 for a mu mismatch; CLOSE), and
  `CAIRN_MPC_SOCKET_DIR=<dir> cargo test -p mpc-bridge` passed 3 of 3 integration tests
  against this backend, including the byte-for-byte deterministic FIPS 204 signature.
- malicious-rep-field-party.x: `local_test.py` passed with `-S 20` (yes); it does not run at
  the default security parameter (see above); the Rust tests were not run against it.
- Linux (added later, outside this directory's original testing): built from the same MP-SPDZ
  commit on Ubuntu 24.04 x86_64 and run for 103 attempts behind a split-host cairn cluster with
  no failed run; mask 1.48 s, response 0.33 s inside MP-SPDZ, same data and round counts as
  above. All three parties were on that one host.
- Not tested: three separate hosts, behaviour under an
  actively deviating MPC party, port collisions between sessions, attempts above 4.
- Not reviewed: the security argument for the openings is the one sketched above and in the
  `.mpc` docstring; it has had no independent review.
