package flamegraph

import (
	"bytes"
	"encoding/gob"
	"errors"
	"math"
	"testing"
)

// gobUint is how encoding/gob itself writes x. The message of a top-level
// uint64 is: length (one byte here), the predefined type ID of uint (one
// byte), the singleton delta 0x00, x.
func gobUint(t *testing.T, x uint64) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(x); err != nil {
		t.Fatal(err)
	}
	msg := buf.Bytes()
	if len(msg) < 4 || int(msg[0]) != len(msg)-1 || msg[2] != 0 {
		t.Fatalf("unexpected gob message for %d: %x", x, msg)
	}
	return msg[3:]
}

var gobUintSamples = []uint64{0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 1 << 32, math.MaxUint64}

func TestAppendGobUintMatchesGob(t *testing.T) {
	for _, x := range gobUintSamples {
		if got, want := appendGobUint(nil, x), gobUint(t, x); !bytes.Equal(got, want) {
			t.Errorf("appendGobUint(%d) = %x, gob writes %x", x, got, want)
		}
	}
	// The documented examples.
	for x, want := range map[uint64][]byte{0: {0x00}, 7: {0x07}, 256: {0xfe, 0x01, 0x00}} {
		if got := appendGobUint(nil, x); !bytes.Equal(got, want) {
			t.Errorf("appendGobUint(%d) = %x, want %x", x, got, want)
		}
	}
}

func TestReadGobUintRoundTrips(t *testing.T) {
	for _, x := range gobUintSamples {
		enc := append(appendGobUint(nil, x), 0xaa) // trailing byte must not be consumed
		got, n, err := readGobUint(enc)
		if err != nil || got != x || n != len(enc)-1 {
			t.Errorf("readGobUint(%x) = %d, %d, %v; want %d, %d, nil", enc, got, n, err, x, len(enc)-1)
		}
	}
}

func TestReadGobIntDecodesSigns(t *testing.T) {
	// gob sends i >= 0 as i<<1 and i < 0 as (^i<<1)|1; the doc's example
	// is -129 -> 257 -> fe 01 01.
	for want, enc := range map[int64][]byte{0: {0x00}, 1: {0x02}, -1: {0x01}, 63: {0x7e}, -129: {0xfe, 0x01, 0x01}} {
		got, n, err := readGobInt(enc)
		if err != nil || got != want || n != len(enc) {
			t.Errorf("readGobInt(%x) = %d, %d, %v; want %d, %d, nil", enc, got, n, err, want, len(enc))
		}
	}
}

func TestReadGobUintRejectsMalformedInput(t *testing.T) {
	for _, enc := range [][]byte{nil, {0xfe, 0x01}, {0xf8}, {0xf7, 1, 2, 3, 4, 5, 6, 7, 8, 9}} {
		if _, _, err := readGobUint(enc); err == nil {
			t.Errorf("readGobUint(%x) succeeded", enc)
		}
	}
	if _, _, err := readGobInt(nil); !errors.Is(err, errGobTruncated) {
		t.Errorf("readGobInt(nil) err = %v, want errGobTruncated", err)
	}
}

func TestSplitGobMessage(t *testing.T) {
	payload, rest, err := splitGobMessage([]byte{0x02, 0xaa, 0xbb, 0xcc})
	if err != nil || !bytes.Equal(payload, []byte{0xaa, 0xbb}) || !bytes.Equal(rest, []byte{0xcc}) {
		t.Fatalf("splitGobMessage = %x, %x, %v; want aabb, cc, nil", payload, rest, err)
	}
	for _, msg := range [][]byte{nil, {0x03, 0xaa, 0xbb}, {0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		if _, _, err := splitGobMessage(msg); !errors.Is(err, errGobTruncated) {
			t.Errorf("splitGobMessage(%x) err = %v, want errGobTruncated", msg, err)
		}
	}
}
