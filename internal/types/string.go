package types

import "bytes"

// As data comes in from arrays, converted to slices, there will be null-bytes at the end..
func StringValue(byteStr []byte) string {
	return string(byteStr[:bytes.IndexByte(byteStr, 0)])
}
