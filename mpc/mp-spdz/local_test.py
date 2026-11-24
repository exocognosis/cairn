#!/usr/bin/env python3
"""Client-side check of a running backend against FIPS 204 semantics computed here in Python.

    local_test.py <socket-dir> [max-attempts]

Plays the three root engines: deals a random key and seed additively, runs MASK / RESPONSE
attempts until one is accepted, and compares every opening with a plain Python computation
(c~, the sum of the y shares, the verdict, the hint, z). Then two fault cases: a response
share that does not match its verification share (FAULT 1, party 2) and a shifted mask share
(FAULT 2). Standard library only; independent of the Rust reference.
"""

import hashlib
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bridge import (GAMMA2, K, L, N, Q, challenge_mul, expand_a, inf_norm, intt, ntt,  # noqa: E402
                    read_frame, sample_in_ball, write_frame)

GAMMA1, BETA, OMEGA, D = 1 << 19, 196, 55, 13


def shake256(data, n):
    return hashlib.shake_256(data).digest(n)


def rand_vec(n):
    return [int.from_bytes(os.urandom(4), "little") % Q for _ in range(n)]


def add(*vs):
    return [sum(c) % Q for c in zip(*vs)]


def sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def split3(v):
    a, b = rand_vec(len(v)), rand_vec(len(v))
    return [a, b, sub(sub(v, a), b)]


def mat_vec(a_hat, v):
    v_hat = [ntt(v[N * s:N * (s + 1)]) for s in range(L)]
    out = []
    for r in range(K):
        acc = [0] * N
        for s in range(L):
            a = a_hat[N * (L * r + s):N * (L * r + s + 1)]
            acc = [(x + p * q) % Q for x, p, q in zip(acc, a, v_hat[s])]
        out.extend(intt(acc))
    return out


def expand_mask(rho_pp, kappa):
    out = []
    for r in range(L):
        v = int.from_bytes(shake256(rho_pp + struct.pack("<H", kappa + r), 640), "little")
        out.extend((GAMMA1 - ((v >> (20 * i)) & 0xFFFFF)) % Q for i in range(N))
    return out


def decompose(r):
    r0 = r % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * GAMMA2), r0


def reference_mask(a_hat, key, mu, attempt):
    y = expand_mask(shake256(key + bytes(32) + mu, 64), 5 * attempt)
    w = mat_vec(a_hat, y)
    w1 = bytearray()
    for i in range(0, K * N, 2):
        w1.append(decompose(w[i])[0] | decompose(w[i + 1])[0] << 4)
    return y, w, shake256(mu + bytes(w1), 48)


def reference_finish(z, r, ct0):
    """None for a rejection, else the hint positions."""
    if inf_norm(z) >= GAMMA1 - BETA:
        return None
    if max(abs(decompose(x)[1]) for x in r) >= GAMMA2 - BETA:
        return None
    if inf_norm(ct0) >= GAMMA2:
        return None
    hint = [i for i in range(K * N) if decompose(r[i])[0] != decompose((r[i] + ct0[i]) % Q)[0]]
    return hint if len(hint) <= OMEGA else None


def call(sock_dir, party, payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.path.join(sock_dir, "p%d.sock" % party))
    write_frame(s, payload)
    reply = read_frame(s)
    s.close()
    return reply


def call_all(sock_dir, payloads):
    replies = [None] * 3

    def one(k):
        replies[k] = call(sock_dir, k + 1, payloads[k])

    threads = [threading.Thread(target=one, args=(k,)) for k in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return replies


def pack(vals):
    return struct.pack("<%dI" % len(vals), *vals)


class Client:
    def __init__(self, sock_dir):
        self.dir = sock_dir
        self.session = os.urandom(32)
        self.rho, self.mu, self.key = os.urandom(32), os.urandom(64), os.urandom(32)
        self.a_hat = expand_a(self.rho)
        s1 = [(4 - os.urandom(1)[0] % 9) % Q for _ in range(L * N)]
        s2 = [(4 - os.urandom(1)[0] % 9) % Q for _ in range(K * N)]
        t = add(mat_vec(self.a_hat, s1), s2)
        self.t0 = []
        for x in t:
            m = x & ((1 << D) - 1)
            self.t0.append((m - (1 << D) if m > 1 << (D - 1) else m) % Q)
        self.s1, self.s2 = s1, s2
        self.s1_k, self.s2_k = split3(s1), split3(s2)
        self.k_k = split3(list(self.key))
        self.T = [add(mat_vec(self.a_hat, self.s1_k[k]), self.s2_k[k]) for k in range(3)]

    def mask(self, attempt):
        start = time.time()
        replies = call_all(self.dir, [
            bytes([1]) + self.session + bytes([k + 1]) + struct.pack("<I", attempt) + self.mu
            + self.rho + pack(self.k_k[k]) for k in range(3)])
        self.mask_seconds = time.time() - start
        ys = []
        for r in replies:
            assert r[0] == 0x81 and len(r) == 1 + 48 + 4 * L * N, "mask failed: %r" % r[:80]
            assert r[1:49] == replies[0][1:49]
            ys.append(list(struct.unpack_from("<%dI" % (L * N), r, 49)))
        return replies[0][1:49], ys

    def respond(self, c_tilde, ys, tamper=None):
        c_hat = ntt(sample_in_ball(c_tilde))
        payloads, zs, rs = [], [], []
        for k in range(3):
            z = add(ys[k], challenge_mul(c_hat, self.s1_k[k], L))
            r = sub(mat_vec(self.a_hat, ys[k]), challenge_mul(c_hat, self.s2_k[k], K))
            if tamper:
                tamper(k, z, r)
            zs.append(z)
            rs.append(r)
            payloads.append(bytes([2]) + self.session + bytes([k + 1]) + pack(z) + pack(r)
                            + pack(self.t0) + b"".join(pack(t) for t in self.T))
        start = time.time()
        replies = call_all(self.dir, payloads)
        self.response_seconds = time.time() - start
        assert all(r == replies[0] for r in replies), "parties saw different openings"
        return replies[0], zs, rs, challenge_mul(c_hat, self.t0, K)


def main():
    sock_dir = sys.argv[1]
    max_attempts = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    cl = Client(sock_dir)
    accepted = False
    for attempt in range(max_attempts):
        c_tilde, ys = cl.mask(attempt)
        y_ref, w_ref, c_ref = reference_mask(cl.a_hat, cl.key, cl.mu, attempt)
        assert c_tilde == c_ref, "c~ differs from the reference"
        assert add(*ys) == y_ref, "y shares do not sum to ExpandMask"
        reply, zs, rs, ct0 = cl.respond(c_tilde, ys)
        z, r = add(*zs), add(*rs)
        expect = reference_finish(z, r, ct0)
        print("attempt %d: c~ and y match; mask %.1f s, response %.1f s; reference says %s"
              % (attempt, cl.mask_seconds, cl.response_seconds,
                 "reject" if expect is None else "accept"), flush=True)
        if expect is None:
            assert reply == bytes([0x82]), "expected REJECT, got %r" % reply[:40]
            continue
        assert reply[0] == 0x83, "expected ACCEPT, got %r" % reply[:40]
        (n,) = struct.unpack_from("<H", reply, 1)
        assert list(struct.unpack_from("<%dH" % n, reply, 3)) == expect, "hint differs"
        assert len(reply) == 3 + 2 * n + 3 * 4 * L * N
        got = struct.unpack_from("<%dI" % (3 * L * N), reply, 3 + 2 * n)
        assert list(got) == zs[0] + zs[1] + zs[2], "opened z shares differ"
        print("accepted: hint (%d positions) and z_1, z_2, z_3 match" % n, flush=True)
        accepted = True
        break
    assert accepted, "no accepted attempt within the limit"

    # a second RESPONSE without a new MASK must not reuse w
    reply, *_ = cl.respond(c_tilde, ys)
    assert reply[:2] == bytes([0x8F, 2]), "stale response not refused: %r" % reply[:40]
    print("stale RESPONSE refused (FAULT 2)", flush=True)

    def bad_r(k, z, r):
        if k == 1:
            r[0] = (r[0] + 1) % Q

    c_tilde, ys = cl.mask(max_attempts)
    reply, *_ = cl.respond(c_tilde, ys, bad_r)
    assert reply[:3] == bytes([0x8F, 1, 2]), "expected blame of party 2: %r" % reply[:40]
    print("bad r share of party 2: FAULT 1 party 2 (%s)" % reply[5:].decode(), flush=True)

    c_tilde, ys = cl.mask(max_attempts + 1)
    ys[2][0] = (ys[2][0] + 1) % Q
    reply, *_ = cl.respond(c_tilde, ys)
    assert reply[:2] == bytes([0x8F, 2]), "expected an unattributed fault: %r" % reply[:40]
    print("shifted mask share: FAULT 2 (%s)" % reply[5:].decode(), flush=True)

    # seed shares that do not sum to bytes
    cl.k_k[0][0] = (cl.k_k[0][0] + 256) % Q
    replies = call_all(sock_dir, [
        bytes([1]) + cl.session + bytes([k + 1]) + struct.pack("<I", 0) + cl.mu + cl.rho
        + pack(cl.k_k[k]) for k in range(3)])
    assert all(r[:2] == bytes([0x8F, 2]) for r in replies), "bad seed not refused: %r" % replies[0][:40]
    print("seed shares not summing to bytes: FAULT 2", flush=True)

    # parties that disagree on mu
    cl.k_k[0][0] = (cl.k_k[0][0] - 256) % Q
    replies = call_all(sock_dir, [
        bytes([1]) + cl.session + bytes([k + 1]) + struct.pack("<I", 0)
        + (cl.mu if k else bytes(64)) + cl.rho + pack(cl.k_k[k]) for k in range(3)])
    assert all(r[:2] == bytes([0x8F, 3]) for r in replies), "mu mismatch not refused: %r" % replies[0][:40]
    print("parties disagreeing on mu: FAULT 3", flush=True)

    assert call(sock_dir, 1, bytes([3]) + cl.session) == bytes([0x84])
    assert call(sock_dir, 2, bytes([3]) + bytes(32)) == bytes([0x84])
    print("CLOSE -> CLOSED", flush=True)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
