package types

import "bytes"

// TruncatedPathSuffix marks a path that was longer than the captured field
// (MAX_FILENAME_LENGTH - 1 bytes) and is reported as its captured prefix plus
// this suffix. It lives here so the producer (getcwd handling in package
// internal) and consumers that repair the byte-wise cut in front of it (the
// Parquet schema) share one definition.
const TruncatedPathSuffix = "..."

// StringValue converts a NUL-terminated byte slice to a Go string.
func StringValue(byteStr []byte) string {
	idx := bytes.IndexByte(byteStr, 0)
	if idx == -1 {
		return string(byteStr)
	}
	return string(byteStr[:idx])
}
