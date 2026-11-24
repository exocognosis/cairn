#!/usr/bin/env python3
"""cairn root-engine bridge: IPC wire protocol <-> one MP-SPDZ party.

One process per party. It listens on <socket-dir>/p<k>.sock, and for each MASK / RESPONSE
request writes this party's MP-SPDZ inputs, runs the party binary on the compiled
mldsa65_root_attempt program, parses the outputs and replies. Python 3 standard library only.

Frame: u32 big-endian length, then the payload; payload[0] is the tag; every other integer is
little-endian; field elements are u32 in [0, q). See README.md for the message layouts.

Each session gets its own working directory (inputs, outputs, MP-SPDZ persistence holding the
shares of w between the two phases) and its own TCP port triple derived from the session id, so
sessions do not interfere. Within a session the phases are sequential.
"""

import argparse
import hashlib
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

Q = 8380417
N = 256
K = 6
L = 5
TAU = 49
GAMMA2 = (Q - 1) // 32
C_TILDE_BYTES = 48
PROGRAM = "mldsa65_root_attempt"

TAG_MASK, TAG_RESPONSE, TAG_CLOSE = 0x01, 0x02, 0x03
TAG_MASK_OK, TAG_REJECT, TAG_ACCEPT, TAG_CLOSED, TAG_FAULT = 0x81, 0x82, 0x83, 0x84, 0x8F
FAULT_BLAME, FAULT_UNATTRIBUTED, FAULT_PROTOCOL = 1, 2, 3

MASK_LEN = 1 + 32 + 1 + 4 + 64 + 32 + 4 * 32
RESPONSE_LEN = 1 + 32 + 1 + 4 * (L * N + K * N + K * N + 3 * K * N)
CLOSE_LEN = 1 + 32
MAX_FRAME = 1 << 20


# --- public ML-DSA-65 arithmetic (FIPS 204), needed for the public inputs ---------------


def _brv8(x):
    return int(f"{x:08b}"[::-1], 2)


ZETAS = [pow(1753, _brv8(i), Q) for i in range(N)]
INV_N = pow(N, Q - 2, Q)


def ntt(poly):
    w = list(poly)
    m, length = 0, 128
    while length >= 1:
        for start in range(0, N, 2 * length):
            m += 1
            z = ZETAS[m]
            for j in range(start, start + length):
                t = z * w[j + length] % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
        length //= 2
    return w


def intt(poly):
    w = list(poly)
    m, length = N, 1
    while length < N:
        for start in range(0, N, 2 * length):
            m -= 1
            z = -ZETAS[m]
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = (t - w[j + length]) * z % Q
        length *= 2
    return [x * INV_N % Q for x in w]


def expand_a(rho):
    """FIPS 204 Algorithm 32; A-hat as a flat list, row r, column s, coefficient j."""
    out = []
    for r in range(K):
        for s in range(L):
            want = 3 * 320
            while True:
                stream = hashlib.shake_128(rho + bytes([s, r])).digest(want)
                poly = []
                for i in range(0, len(stream) - 2, 3):
                    v = stream[i] | stream[i + 1] << 8 | (stream[i + 2] & 0x7F) << 16
                    if v < Q:
                        poly.append(v)
                        if len(poly) == N:
                            break
                if len(poly) == N:
                    break
                want *= 2
            out.extend(poly)
    return out


def sample_in_ball(c_tilde):
    """FIPS 204 Algorithm 29."""
    want = 8 + 512
    while True:
        stream = hashlib.shake_256(c_tilde).digest(want)
        signs = int.from_bytes(stream[:8], "little")
        c, pos, ok = [0] * N, 8, True
        for i in range(N - TAU, N):
            while True:
                if pos >= len(stream):
                    ok = False
                    break
                j = stream[pos]
                pos += 1
                if j <= i:
                    break
            if not ok:
                break
            c[i] = c[j]
            c[j] = Q - 1 if (signs >> (i + TAU - N)) & 1 else 1
        if ok:
            return c
        want *= 2


def challenge_mul(c_hat, flat, polys):
    """c * v for a flat coefficient-domain vector of `polys` polynomials."""
    out = []
    for p in range(polys):
        v_hat = ntt(flat[N * p:N * (p + 1)])
        out.extend(intt([a * b % Q for a, b in zip(c_hat, v_hat)]))
    return out


def inf_norm(flat):
    return max(min(x, Q - x) for x in flat)


# --- wire helpers ----------------------------------------------------------------------


def read_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_frame(conn):
    head = read_exact(conn, 4)
    if head is None:
        return None
    (length,) = struct.unpack(">I", head)
    if length == 0 or length > MAX_FRAME:
        raise ValueError("bad frame length %d" % length)
    return read_exact(conn, length)


def write_frame(conn, payload):
    conn.sendall(struct.pack(">I", len(payload)) + payload)


def fault(code, party, text):
    msg = text.encode("utf-8")[:1000]
    return bytes([TAG_FAULT, code, party]) + struct.pack("<H", len(msg)) + msg


def u32s(data, count, offset):
    return list(struct.unpack_from("<%dI" % count, data, offset)), offset + 4 * count


class ProtocolError(Exception):
    pass


def field_elements(data, count, offset, what):
    vals, offset = u32s(data, count, offset)
    if any(v >= Q for v in vals):
        raise ProtocolError(what + " has an element outside [0, q)")
    return vals, offset


# --- one MP-SPDZ party -----------------------------------------------------------------


class Bridge:
    def __init__(self, args):
        self.party = args.party                # 1..3 on the wire, 0..2 in MP-SPDZ
        self.player = args.party - 1
        self.mpspdz = os.path.abspath(args.mpspdz_dir)
        self.programs = os.path.abspath(args.program_dir)
        self.work = os.path.abspath(os.path.join(args.work_dir, "p%d" % args.party))
        self.hosts = args.hosts.split(",")
        if len(self.hosts) != 3:
            raise SystemExit("--hosts needs three comma-separated host names")
        self.port_base = args.port_base
        self.timeout = args.timeout
        self.unencrypted = args.unencrypted
        self.extra_args = args.party_arg or []
        self.ssl_dir = os.path.abspath(args.ssl_dir) if args.ssl_dir else None
        self.binary = os.path.join(self.mpspdz, args.protocol + "-party.x")
        if not os.access(self.binary, os.X_OK):
            raise SystemExit("party binary not found: " + self.binary)
        for phase in ("mask", "response"):
            sch = os.path.join(self.programs, "Schedules", "%s-%s.sch" % (PROGRAM, phase))
            if not os.path.exists(sch):
                raise SystemExit("compiled program missing: " + sch)
        if not self.unencrypted and not self.ssl_dir:
            raise SystemExit("give --ssl-dir (P0..P2.pem, own key, hash links) or --unencrypted")
        self.sessions = {}                     # session -> dict(lock, dir, ...)
        self.sessions_lock = threading.Lock()
        self.a_hat_cache = {}
        shutil.rmtree(self.work, ignore_errors=True)
        os.makedirs(self.work, mode=0o700)

    def log(self, text):
        sys.stderr.write("[bridge p%d] %s\n" % (self.party, text))
        sys.stderr.flush()

    # session bookkeeping

    def session_state(self, session, create):
        with self.sessions_lock:
            st = self.sessions.get(session)
            if st is None and create:
                st = {"lock": threading.Lock(), "pending": None,
                      "dir": os.path.join(self.work, hashlib.shake_256(session).hexdigest(8))}
                self.sessions[session] = st
            return st

    def session_port(self, session):
        # The three parties derive the same port triple from the session id.
        slot = int.from_bytes(hashlib.shake_256(b"cairn/mp-spdz/port" + session).digest(4), "little")
        return self.port_base + 3 * (slot % 2000)

    def prepare_dir(self, st, session):
        d = st["dir"]
        if os.path.isdir(d):
            return
        os.makedirs(os.path.join(d, "Programs", "Public-Input"), mode=0o700)
        os.makedirs(os.path.join(d, "Player-Data"), mode=0o700)
        os.makedirs(os.path.join(d, "Persistence"), mode=0o700)
        for sub in ("Bytecode", "Schedules"):
            os.symlink(os.path.join(self.programs, sub), os.path.join(d, "Programs", sub))
        if self.ssl_dir:
            for name in os.listdir(self.ssl_dir):
                if name.endswith((".pem", ".0")) or name == "P%d.key" % self.player:
                    os.symlink(os.path.join(self.ssl_dir, name), os.path.join(d, "Player-Data", name))
        with open(os.path.join(d, "hosts"), "w") as f:
            f.write("\n".join(self.hosts) + "\n")
        st["port"] = self.session_port(session)

    def a_hat(self, rho):
        if rho not in self.a_hat_cache:
            if len(self.a_hat_cache) > 16:
                self.a_hat_cache.clear()
            self.a_hat_cache[rho] = expand_a(rho)
        return self.a_hat_cache[rho]

    # running the party

    def run_party(self, st, phase, private, public):
        """Run one phase; returns the stdout lines, or raises RuntimeError / TimeoutError."""
        d = st["dir"]
        prog = "%s-%s" % (PROGRAM, phase)
        priv_path = os.path.join(d, "Player-Data", "Input-P%d-0" % self.player)
        out_path = os.path.join(d, "Player-Data", "Binary-Output-P%d-0" % self.player)
        if os.path.exists(out_path):
            os.remove(out_path)
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(" ".join(map(str, private)) + "\n")
        with open(os.path.join(d, "Programs", "Public-Input", prog), "w") as f:
            f.write(" ".join(map(str, public)) + "\n")
        cmd = [self.binary, "-p", str(self.player), "-P", str(Q), "-ip", "hosts",
               "-pn", str(st["port"]), "-OF", "."]  # -OF .: program output on every party
        if self.unencrypted:
            cmd.append("-u")
        cmd.extend(self.extra_args)
        cmd.append(prog)
        # libSPDZ.so sits next to the binary; the binary may not carry an rpath (macOS).
        env = dict(os.environ)
        for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            env[var] = self.mpspdz + (os.pathsep + env[var] if env.get(var) else "")
        start = time.time()
        log_path = os.path.join(d, phase + ".stderr")
        try:
            with open(log_path, "w") as err:
                done = subprocess.run(cmd, cwd=d, stdout=subprocess.PIPE, stderr=err,
                                      stdin=subprocess.DEVNULL, timeout=self.timeout, env=env)
        except subprocess.TimeoutExpired:
            raise TimeoutError("MP-SPDZ %s phase timed out after %d s" % (phase, self.timeout))
        finally:
            try:
                os.remove(priv_path)
            except OSError:
                pass
        stats = []
        with open(log_path, errors="replace") as err:
            for line in err:
                if re.match(r"(Time|Data sent|Global data sent)\b", line):
                    stats.append(line.strip())
        self.log("%s: exit %d, %.1f s wall; %s" % (phase, done.returncode, time.time() - start,
                                                   "; ".join(stats)))
        lines = done.stdout.decode("utf-8", "replace").splitlines()
        if done.returncode != 0 or ("%s_%s_complete" % ("mldsa65_root", phase)) not in lines:
            raise RuntimeError("MP-SPDZ %s phase aborted (exit %d), see %s"
                               % (phase, done.returncode, log_path))
        return lines

    @staticmethod
    def program_fault(lines):
        for line in lines:
            m = re.match(r"fault (\d+) (-?\d+) (.*)", line)
            if m:
                return fault(int(m.group(1)), int(m.group(2)) % Q, m.group(3))
        return None

    @staticmethod
    def int_list(line):
        return [int(t) % Q for t in re.findall(r"-?\d+", line.split(" ", 1)[1])]

    # requests

    def handle_mask(self, data):
        if len(data) != MASK_LEN:
            return fault(FAULT_PROTOCOL, 0, "bad MASK length")
        session, party = data[1:33], data[33]
        (attempt,) = struct.unpack_from("<I", data, 34)
        mu, rho = data[38:102], data[102:134]
        if party != self.party:
            return fault(FAULT_PROTOCOL, 0, "MASK for party %d sent to party %d" % (party, self.party))
        if 5 * attempt + L - 1 > 0xFFFF:
            return fault(FAULT_PROTOCOL, 0, "attempt counter too large")
        k_share, _ = field_elements(data, 32, 134, "k_share")
        st = self.session_state(session, True)
        with st["lock"]:
            st["pending"] = None
            self.prepare_dir(st, session)
            persistence = os.path.join(st["dir"], "Persistence", "Transactions-P%d.data" % self.player)
            if os.path.exists(persistence):
                os.remove(persistence)
            digest = hashlib.shake_256(b"cairn/mp-spdz/mask/v1" + session + data[34:38] + mu + rho).digest(32)
            mu_bits = [(mu[i // 8] >> (i % 8)) & 1 for i in range(512)]
            nonce_bits = [((5 * attempt + r) >> b) & 1 for r in range(L) for b in range(16)]
            lines = self.run_party(st, "mask", list(digest) + k_share,
                                   mu_bits + nonce_bits + self.a_hat(rho))
            reply = self.program_fault(lines)
            if reply:
                return reply
            if "mask_ok" not in lines:
                raise RuntimeError("mask phase printed no result")
            c_tilde = bytes(int(l.split()[1]) % Q for l in lines if l.startswith("ctilde_byte "))
            if len(c_tilde) != C_TILDE_BYTES:
                raise RuntimeError("mask phase printed %d c~ bytes" % len(c_tilde))
            out_path = os.path.join(st["dir"], "Player-Data", "Binary-Output-P%d-0" % self.player)
            with open(out_path, "rb") as f:
                raw = f.read()
            os.remove(out_path)
            if len(raw) != 8 * L * N:
                raise RuntimeError("private output has %d bytes" % len(raw))
            y_share = [v % Q for v in struct.unpack("<%dq" % (L * N), raw)]
            st["pending"] = {"c_tilde": c_tilde, "rho": rho}
            return bytes([TAG_MASK_OK]) + c_tilde + struct.pack("<%dI" % (L * N), *y_share)

    def handle_response(self, data):
        if len(data) != RESPONSE_LEN:
            return fault(FAULT_PROTOCOL, 0, "bad RESPONSE length")
        session, party = data[1:33], data[33]
        if party != self.party:
            return fault(FAULT_PROTOCOL, 0, "RESPONSE for party %d sent to party %d" % (party, self.party))
        z_share, off = field_elements(data, L * N, 34, "z_share")
        r_share, off = field_elements(data, K * N, off, "r_share")
        public_bytes = data[off:]
        t0, off = field_elements(data, K * N, off, "t0")
        t = []
        for _ in range(3):
            t_k, off = field_elements(data, K * N, off, "T")
            t.append(t_k)
        st = self.session_state(session, False)
        if st is None:
            return fault(FAULT_UNATTRIBUTED, 0, "no mask phase is pending for this session")
        with st["lock"]:
            pending, st["pending"] = st["pending"], None  # w is single-use
            if pending is None:
                return fault(FAULT_UNATTRIBUTED, 0, "no mask phase is pending for this session")
            c_tilde = pending["c_tilde"]
            digest = hashlib.shake_256(b"cairn/mp-spdz/response/v1" + session + c_tilde
                                       + public_bytes).digest(32)
            c_hat = ntt(sample_in_ball(c_tilde))
            ct = [challenge_mul(c_hat, t_k, K) for t_k in t]
            ct0 = challenge_mul(c_hat, t0, K)
            ct0_ok = 1 if inf_norm(ct0) < GAMMA2 else 0
            try:
                lines = self.run_party(st, "response", list(digest) + z_share + r_share,
                                       self.a_hat(pending["rho"]) + ct[0] + ct[1] + ct[2] + ct0 + [ct0_ok])
            finally:
                persistence = os.path.join(st["dir"], "Persistence", "Transactions-P%d.data" % self.player)
                if os.path.exists(persistence):
                    os.remove(persistence)
            reply = self.program_fault(lines)
            if reply:
                return reply
            if "reject" in lines:
                return bytes([TAG_REJECT])
            if "accept" not in lines:
                raise RuntimeError("response phase printed no verdict")
            found = {l.split(" ", 1)[0]: self.int_list(l) for l in lines
                     if re.match(r"(h|z1|z2|z3) ", l)}
            h = found.get("h", [])
            zs = [found.get("z%d" % p, []) for p in (1, 2, 3)]
            if len(h) != K * N or any(len(z) != L * N for z in zs) or any(b not in (0, 1) for b in h):
                raise RuntimeError("malformed accept output")
            positions = [i for i, b in enumerate(h) if b]
            out = bytes([TAG_ACCEPT]) + struct.pack("<H", len(positions))
            out += struct.pack("<%dH" % len(positions), *positions)
            for z in zs:
                out += struct.pack("<%dI" % (L * N), *z)
            return out

    def handle_close(self, data):
        if len(data) != CLOSE_LEN:
            return fault(FAULT_PROTOCOL, 0, "bad CLOSE length")
        with self.sessions_lock:
            st = self.sessions.pop(data[1:33], None)
        if st is not None:
            with st["lock"]:
                st["pending"] = None
                shutil.rmtree(st["dir"], ignore_errors=True)
        return bytes([TAG_CLOSED])

    def handle(self, data):
        try:
            if data[0] == TAG_MASK:
                return self.handle_mask(data)
            if data[0] == TAG_RESPONSE:
                return self.handle_response(data)
            if data[0] == TAG_CLOSE:
                return self.handle_close(data)
            return fault(FAULT_PROTOCOL, 0, "unknown request tag 0x%02x" % data[0])
        except ProtocolError as e:
            return fault(FAULT_PROTOCOL, 0, str(e))
        except TimeoutError as e:
            self.log(str(e))
            return fault(FAULT_PROTOCOL, 0, str(e))
        except RuntimeError as e:
            # The MPC stopped without a verdict (a peer vanished, a check of the malicious
            # protocol failed, ...): nothing was opened, and no party can be named.
            self.log(str(e))
            return fault(FAULT_UNATTRIBUTED, 0, str(e))
        except Exception as e:  # keep the listener alive
            self.log("internal error: %r" % (e,))
            return fault(FAULT_PROTOCOL, 0, "bridge internal error")

    def serve_connection(self, conn):
        try:
            while True:
                data = read_frame(conn)
                if data is None:
                    return
                write_frame(conn, self.handle(data))
        except (OSError, ValueError) as e:
            self.log("connection dropped: %s" % e)
        finally:
            conn.close()

    def serve(self, socket_dir):
        os.makedirs(socket_dir, exist_ok=True)
        path = os.path.join(socket_dir, "p%d.sock" % self.party)
        if os.path.exists(path):
            os.remove(path)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o077)
        try:
            server.bind(path)
        finally:
            os.umask(old)
        server.listen(16)
        self.log("listening on %s (%s)" % (path, os.path.basename(self.binary)))
        try:
            while True:
                conn, _ = server.accept()
                threading.Thread(target=self.serve_connection, args=(conn,), daemon=True).start()
        finally:
            server.close()
            os.remove(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--party", type=int, required=True, choices=(1, 2, 3))
    ap.add_argument("--socket-dir", required=True)
    ap.add_argument("--mpspdz-dir", required=True, help="MP-SPDZ checkout holding the party binaries")
    ap.add_argument("--program-dir", required=True,
                    help="directory holding Bytecode/ and Schedules/ of the compiled program")
    ap.add_argument("--work-dir", required=True, help="scratch directory (per-session state)")
    ap.add_argument("--hosts", required=True, help="host1,host2,host3 of wire parties 1,2,3")
    ap.add_argument("--port-base", type=int, default=14000,
                    help="sessions use ports in [base, base + 6000)")
    ap.add_argument("--protocol", default="replicated-field",
                    choices=("replicated-field", "malicious-rep-field"))
    ap.add_argument("--ssl-dir", help="P0.pem..P2.pem, this party's key and the c_rehash links")
    ap.add_argument("--unencrypted", action="store_true",
                    help="pass -u to MP-SPDZ (no TLS between parties; local tests only)")
    ap.add_argument("--party-arg", action="append", metavar="ARG",
                    help="extra argument for the party binary (repeatable), e.g. --party-arg=-S --party-arg=20")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per phase")
    args = ap.parse_args()
    bridge = Bridge(args)
    try:
        bridge.serve(args.socket_dir)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
