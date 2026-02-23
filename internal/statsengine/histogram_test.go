package statsengine

import (
	"reflect"
	"testing"
)

func TestHistogramBucketIndexBoundaries(t *testing.T) {
	tests := []struct {
		name string
		dur  uint64
		idx  int
	}{
		{name: "zero", dur: 0, idx: 0},
		{name: "just below 1us", dur: 999, idx: 0},
		{name: "at 1us", dur: 1_000, idx: 1},
		{name: "at 10us", dur: 10_000, idx: 2},
		{name: "at 100us", dur: 100_000, idx: 3},
		{name: "at 1ms", dur: 1_000_000, idx: 4},
		{name: "at 10ms", dur: 10_000_000, idx: 5},
		{name: "at 100ms", dur: 100_000_000, idx: 6},
		{name: "at 1s", dur: 1_000_000_000, idx: 7},
		{name: "above 1s", dur: 5_000_000_000, idx: 7},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := histogramBucketIndex(tc.dur); got != tc.idx {
				t.Fatalf("wrong bucket index for %d: got %d want %d", tc.dur, got, tc.idx)
			}
		})
	}
}

func TestHistogramSnapshotCountsAndRanges(t *testing.T) {
	h := newHistogram()

	h.Increment(0)
	h.Increment(1_000)
	h.Increment(1_000)
	h.Increment(1_500_000_000)

	snap := h.Snapshot()
	if snap.Total != 4 {
		t.Fatalf("wrong total: got %d want 4", snap.Total)
	}

	buckets := snap.Buckets()
	if len(buckets) != histogramBucketCount {
		t.Fatalf("wrong bucket count: got %d want %d", len(buckets), histogramBucketCount)
	}

	if buckets[0].Count != 1 || buckets[1].Count != 2 || buckets[7].Count != 1 {
		t.Fatalf("unexpected bucket counts: %+v", buckets)
	}

	if buckets[0].LowerNs != 0 || buckets[0].UpperNs != 1_000 {
		t.Fatalf("unexpected first range: %+v", buckets[0])
	}
	if buckets[7].LowerNs != 1_000_000_000 || buckets[7].UpperNs != 0 {
		t.Fatalf("unexpected last range: %+v", buckets[7])
	}
}

func TestHistogramSnapshotIsDefensive(t *testing.T) {
	h := newHistogram()
	h.Increment(1)

	s1 := h.Snapshot()
	b1 := s1.Buckets()
	b1[0].Count = 99

	s2 := h.Snapshot()
	if got := s2.Buckets()[0].Count; got != 1 {
		t.Fatalf("snapshot leaked mutable buckets: got %d", got)
	}

	if reflect.DeepEqual(b1, s2.Buckets()) {
		t.Fatalf("expected defensive copies of buckets")
	}
}

func TestNilHistogramSnapshot(t *testing.T) {
	var h *histogram
	s := h.Snapshot()
	if s.Total != 0 {
		t.Fatalf("expected zero total, got %d", s.Total)
	}
	if got := s.Buckets(); got != nil {
		t.Fatalf("expected nil buckets, got %#v", got)
	}
}
