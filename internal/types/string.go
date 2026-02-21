package types

import "bytes"

// As data comes in from arrays, converted to slices, there will be null-bytes at the end..
func StringValue(byteStr []byte) string {
	idx := bytes.IndexByte(byteStr, 0)
	if idx == -1 {
		return string(byteStr)
	}
	return string(byteStr[:idx])
}
