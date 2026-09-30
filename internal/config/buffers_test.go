package config

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// mapsHEventMapEntries extracts the max_entries that internal/c/maps.h
// declares for event_map, evaluating the "1 << N" / plain-integer spellings.
func mapsHEventMapEntries(t *testing.T) uint64 {
	t.Helper()
	src, err := os.ReadFile("../c/maps.h")
	if err != nil {
		t.Fatalf("read maps.h: %v", err)
	}
	re := regexp.MustCompile(`(?s)__uint\(max_entries,\s*(?:1\s*<<\s*(\d+)|(\d+))\s*\);\s*\}\s*event_map\s+SEC`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatal("event_map max_entries declaration not found in maps.h")
	}
	if len(m[1]) > 0 {
		shift, _ := strconv.ParseUint(string(m[1]), 10, 6)
		return 1 << shift
	}
	n, _ := strconv.ParseUint(string(m[2]), 10, 64)
	return n
}

// TestDefaultEventMapSizeMatchesMapsH pins that the Go default and the
// declaration in the BPF source agree. resizeBPFMaps overwrites maps.h's value
// at load time, so a mismatch means the declared 16 MiB is a lie (it was:
// 64 KiB in Go vs 16 MiB in C, and bursty loads dropped events).
func TestDefaultEventMapSizeMatchesMapsH(t *testing.T) {
	if got, want := uint64(DefaultEventMapSize), mapsHEventMapEntries(t); got != want {
		t.Fatalf("DefaultEventMapSize = %d, maps.h event_map max_entries = %d; keep them equal", got, want)
	}
}

// TestDefaultEventMapSizeIsAValidRingbufSize requires the default to be a
// power of two that is a whole number of pages (up to 64 KiB pages), so libbpf
// passes it through unrounded on every architecture.
func TestDefaultEventMapSizeIsAValidRingbufSize(t *testing.T) {
	const maxPage = 64 << 10
	n := uint64(DefaultEventMapSize)
	if n == 0 || n&(n-1) != 0 || n < maxPage {
		t.Fatalf("DefaultEventMapSize = %d, want a power of two >= %d", n, maxPage)
	}
}
