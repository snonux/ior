package internal

import (
	"math"
	"testing"
)

// decodeSamplingRate mirrors ior_sampling_rate in internal/c/filter.c: a
// slot of 0 (never written, or an ID past the array) is the default rate 1,
// any other value is rate + 1.
func decodeSamplingRate(stored uint32) uint32 {
	if stored == 0 {
		return 1
	}
	return stored - 1
}

// TestEncodeSamplingRateRoundTripsThroughTheBPFDecoder pins the array map's
// rate + 1 encoding (task 2s2): the aggregate-only rate 0 must not collide
// with the "not configured" slot value 0, and the largest rate must not
// wrap to it.
func TestEncodeSamplingRateRoundTripsThroughTheBPFDecoder(t *testing.T) {
	for _, rate := range []uint32{0, 1, 2, 10, 200, 1 << 20, math.MaxUint32 - 2} {
		stored := encodeSamplingRate(rate)
		if stored == 0 {
			t.Fatalf("rate %d encodes to 0, which the BPF side reads as 'not configured'", rate)
		}
		if got := decodeSamplingRate(stored); got != rate {
			t.Errorf("rate %d round-trips to %d (stored %d)", rate, got, stored)
		}
	}
	if got := decodeSamplingRate(encodeSamplingRate(math.MaxUint32)); got != math.MaxUint32-1 {
		t.Errorf("the maximum rate decodes to %d, want it saturated at %d", got, uint32(math.MaxUint32-1))
	}
	if got := decodeSamplingRate(0); got != 1 {
		t.Errorf("an unconfigured slot decodes to rate %d, want the default 1", got)
	}
}
