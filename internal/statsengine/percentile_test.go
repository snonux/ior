package statsengine

import (
	"math/rand/v2"
	"slices"
	"testing"
)

// percentileInputShapes returns generators for sample slices of length n
// covering the shapes that stress a quickselect: random, heavy duplicates,
// constant, already ordered in either direction and organ-pipe.
func percentileInputShapes(rng *rand.Rand) map[string]func(n int) []uint64 {
	fill := func(n int, f func(i int) uint64) []uint64 {
		s := make([]uint64, n)
		for i := range s {
			s[i] = f(i)
		}
		return s
	}
	return map[string]func(n int) []uint64{
		"random":       func(n int) []uint64 { return fill(n, func(int) uint64 { return rng.Uint64N(1_000_000) }) },
		"few distinct": func(n int) []uint64 { return fill(n, func(int) uint64 { return rng.Uint64N(3) }) },
		"all equal":    func(n int) []uint64 { return fill(n, func(int) uint64 { return 7 }) },
		"ascending":    func(n int) []uint64 { return fill(n, func(i int) uint64 { return uint64(i) }) },
		"descending":   func(n int) []uint64 { return fill(n, func(i int) uint64 { return uint64(n - i) }) },
		"organ pipe":   func(n int) []uint64 { return fill(n, func(i int) uint64 { return uint64(min(i, n-i)) }) },
	}
}

// TestLatencyPercentilesMatchSortOracle checks that the selection-based
// percentiles are exactly those of a full sort for many input shapes.
func TestLatencyPercentilesMatchSortOracle(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 16, 17, 99, 100, 101, 1_000, syscallReservoirSampleCapDefault}
	for name, gen := range percentileInputShapes(rand.New(rand.NewPCG(99, 1))) {
		for _, n := range sizes {
			samples := gen(n)
			wantP50, wantP95, wantP99 := referencePercentiles(samples)
			gotP50, gotP95, gotP99 := latencyPercentiles(samples)
			if gotP50 != wantP50 || gotP95 != wantP95 || gotP99 != wantP99 {
				t.Fatalf("%s n=%d: got %d/%d/%d, want %d/%d/%d", name, n, gotP50, gotP95, gotP99, wantP50, wantP95, wantP99)
			}
		}
	}
}

func TestSelectNthPartitionsAroundK(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 5))
	for iter := 0; iter < 500; iter++ {
		n := 1 + rng.IntN(300)
		s := make([]uint64, n)
		for i := range s {
			s[i] = rng.Uint64N(50)
		}
		sorted := slices.Sorted(slices.Values(s))
		k := rng.IntN(n)

		selectNth(s, k)
		if s[k] != sorted[k] {
			t.Fatalf("n=%d k=%d: s[k]=%d, want %d", n, k, s[k], sorted[k])
		}
		for i := range s {
			if (i < k && s[i] > s[k]) || (i > k && s[i] < s[k]) {
				t.Fatalf("n=%d k=%d: element %d=%d on the wrong side of %d", n, k, i, s[i], s[k])
			}
		}
		if !slices.Equal(slices.Sorted(slices.Values(s)), sorted) {
			t.Fatalf("n=%d k=%d: selectNth changed the multiset", n, k)
		}
	}
}

func TestPercentileRankBounds(t *testing.T) {
	tests := []struct {
		n    int
		p    float64
		want int
	}{
		{n: 1, p: 0.5, want: 0},
		{n: 10, p: 0, want: 0},
		{n: 10, p: -1, want: 0},
		{n: 10, p: 1, want: 9},
		{n: 10, p: 2, want: 9},
		{n: 10, p: 0.5, want: 4},
		{n: 10, p: 0.95, want: 9},
		{n: 100, p: 0.99, want: 98},
		{n: 101, p: 0.99, want: 99},
	}
	for _, tc := range tests {
		if got := percentileRank(tc.n, tc.p); got != tc.want {
			t.Fatalf("percentileRank(%d, %v) = %d, want %d", tc.n, tc.p, got, tc.want)
		}
	}
}

func BenchmarkLatencyPercentilesSelect(b *testing.B) {
	benchmarkPercentiles(b, func(s []uint64) { _, _, _ = latencyPercentiles(s) })
}

func BenchmarkLatencyPercentilesSort(b *testing.B) {
	benchmarkPercentiles(b, func(s []uint64) { _, _, _ = referencePercentiles(s) })
}

func benchmarkPercentiles(b *testing.B, fn func([]uint64)) {
	rng := rand.New(rand.NewPCG(1, 2))
	src := make([]uint64, syscallReservoirSampleCapDefault)
	for i := range src {
		src[i] = rng.Uint64N(100_000)
	}
	work := make([]uint64, len(src))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(work, src)
		fn(work)
	}
}
