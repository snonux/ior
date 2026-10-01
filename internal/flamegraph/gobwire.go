package flamegraph

import (
	"errors"
	"math/bits"
)

// The few pieces of the gob wire format that writeRecordsMessage needs to
// frame the records message itself (recordsgob.go). They follow "Encoding
// details" in the encoding/gob documentation:
//
//   - an unsigned integer below 128 is one byte holding the value; a larger
//     one is a byte holding the negated byte count (-1..-8) followed by the
//     value in big-endian order with no leading zero bytes;
//   - a signed integer i is sent as the unsigned integer (i << 1) for i >= 0
//     and (^i << 1) | 1 for i < 0;
//   - a message is an unsigned length followed by that many bytes.

var errGobTruncated = errors.New("truncated gob data")

// appendGobUint appends x in gob's unsigned integer encoding.
func appendGobUint(b []byte, x uint64) []byte {
	if x < 0x80 {
		return append(b, byte(x))
	}
	n := (bits.Len64(x) + 7) / 8
	b = append(b, byte(-n))
	for shift := 8 * (n - 1); shift >= 0; shift -= 8 {
		b = append(b, byte(x>>shift))
	}
	return b
}

// readGobUint decodes an unsigned integer from the start of b and returns it
// with the number of bytes it occupied.
func readGobUint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errGobTruncated
	}
	if b[0] < 0x80 {
		return uint64(b[0]), 1, nil
	}
	n := -int(int8(b[0]))
	if n > 8 {
		return 0, 0, errors.New("invalid gob unsigned integer")
	}
	if len(b) < 1+n {
		return 0, 0, errGobTruncated
	}
	var x uint64
	for _, d := range b[1 : 1+n] {
		x = x<<8 | uint64(d)
	}
	return x, 1 + n, nil
}

// readGobInt decodes a signed integer from the start of b and returns it with
// the number of bytes it occupied.
func readGobInt(b []byte) (int64, int, error) {
	u, n, err := readGobUint(b)
	if err != nil {
		return 0, 0, err
	}
	if u&1 != 0 {
		return int64(^(u >> 1)), n, nil
	}
	return int64(u >> 1), n, nil
}

// splitGobMessage splits the first message off b and returns its payload
// (without the length) and the bytes after it.
func splitGobMessage(b []byte) (payload, rest []byte, err error) {
	size, n, err := readGobUint(b)
	if err != nil {
		return nil, nil, err
	}
	if size > uint64(len(b)-n) {
		return nil, nil, errGobTruncated
	}
	end := n + int(size)
	return b[n:end], b[end:], nil
}
