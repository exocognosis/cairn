// Harness that lets cairn drive the authors' reference implementation of threshold
// ML-DSA-65 one protocol step at a time. scripts/reference-interop.sh copies this file
// into the reference's thmldsa65/internal package and cairn's interop test runs it.
// It only calls the reference's own functions; all values cross as raw little-endian u32.
package internal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

func ciEnv(t *testing.T, k string) string {
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("missing %s", k)
	}
	return v
}

func ciNum(t *testing.T, k string) int {
	n, err := strconv.Atoi(ciEnv(t, k))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func ciIds(t *testing.T, k string) []uint8 {
	var out []uint8
	for _, s := range strings.Split(os.Getenv(k), ",") {
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, uint8(n))
	}
	return out
}

func ciPut(buf *bytes.Buffer, ps []common.Poly) {
	for i := range ps {
		for _, c := range ps[i] {
			_ = binary.Write(buf, binary.LittleEndian, c)
		}
	}
}

func ciGet(b []byte, ps []common.Poly) []byte {
	for i := range ps {
		for j := range ps[i] {
			ps[i][j] = binary.LittleEndian.Uint32(b)
			b = b[4:]
		}
	}
	return b
}

func ciReadW(t *testing.T, path string, reps uint16) []VecK {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ws := make([]VecK, reps)
	for i := range ws {
		b = ciGet(b, ws[i][:])
	}
	return ws
}

func ciReadZ(t *testing.T, path string, reps uint16) []VecL {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zs := make([]VecL, reps)
	for i := range zs {
		b = ciGet(b, zs[i][:])
	}
	return zs
}

func TestCairnInterop(t *testing.T) {
	mode := os.Getenv("CAIRN_MODE")
	if mode == "" {
		t.Skip("driven by cairn")
	}
	dir := ciEnv(t, "CAIRN_DIR")
	params, err := GetThresholdParams(uint8(ciNum(t, "CAIRN_T")), uint8(ciNum(t, "CAIRN_N")))
	if err != nil {
		t.Fatal(err)
	}
	var seed [common.SeedSize]byte
	s, _ := hex.DecodeString(ciEnv(t, "CAIRN_SEED"))
	copy(seed[:], s)
	pk, sks := NewThresholdKeysFromSeed(&seed, params)
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rhop := func(id uint8) (r [64]byte) {
		b, _ := hex.DecodeString(ciEnv(t, "CAIRN_RHOP"))
		copy(r[:], b)
		r[63] = id
		return
	}
	msg := func(w io.Writer) {
		b, _ := hex.DecodeString(os.Getenv("CAIRN_MSG"))
		_, _ = w.Write(b)
	}

	switch mode {
	case "keygen":
		var buf bytes.Buffer
		var pkb [PublicKeySize]byte
		pk.Pack(&pkb)
		buf.Write(pk.rho[:])
		buf.Write(pkb[:])
		shares := map[uint8]*Share{}
		for i := range sks {
			for m, sh := range sks[i].shares {
				shares[m] = sh
			}
		}
		masks := make([]int, 0, len(shares))
		for m := range shares {
			masks = append(masks, int(m))
		}
		sort.Ints(masks)
		buf.WriteByte(byte(len(masks)))
		for _, m := range masks {
			buf.WriteByte(byte(m))
			ciPut(&buf, shares[uint8(m)].s1[:])
			ciPut(&buf, shares[uint8(m)].s2[:])
		}
		write("keys.bin", buf.Bytes())
	case "commit":
		for _, id := range ciIds(t, "CAIRN_IDS") {
			ws, _ := GenThCommitment(&sks[id], rhop(id), 0, params)
			var buf bytes.Buffer
			for i := range ws {
				ciPut(&buf, ws[i][:])
			}
			write("w_"+strconv.Itoa(int(id))+".bin", buf.Bytes())
		}
	case "respond":
		act := uint8(ciNum(t, "CAIRN_ACT"))
		for _, id := range ciIds(t, "CAIRN_IDS") {
			wfinals := ciReadW(t, filepath.Join(dir, "wfinal.bin"), params.K)
			_, stws := GenThCommitment(&sks[id], rhop(id), 0, params)
			mu := ComputeMu(&sks[id], msg)
			zs := ComputeResponses(&sks[id], act, mu, wfinals, stws, params)
			var buf bytes.Buffer
			for i := range zs {
				ciPut(&buf, zs[i][:])
			}
			write("z_"+strconv.Itoa(int(id))+".bin", buf.Bytes())
		}
	case "combine":
		wfinals := ciReadW(t, filepath.Join(dir, "wfinal.bin"), params.K)
		zfinals := make([]VecL, params.K)
		for _, id := range ciIds(t, "CAIRN_IDS") {
			AggregateResponses(zfinals, ciReadZ(t, filepath.Join(dir, "z_"+strconv.Itoa(int(id))+".bin"), params.K))
		}
		sig := make([]byte, SignatureSize)
		if !Combine(pk, msg, wfinals, zfinals, sig, params) {
			write("sig.bin", nil)
			return
		}
		if !Verify(pk, msg, sig) {
			t.Fatal("reference Verify rejected the reference Combine output")
		}
		write("sig.bin", sig)
	default:
		t.Fatalf("unknown mode %s", mode)
	}
}
