package types

import "bytes"

// StringValue converts a NUL-terminated byte slice to a Go string.
func StringValue(byteStr []byte) string {
	idx := bytes.IndexByte(byteStr, 0)
	if idx == -1 {
		return string(byteStr)
	}
	return string(byteStr[:idx])
}
