package statsengine

import (
	"math"
	"math/bits"
	"slices"
)

// selectSmallRange is the range length below which selectNth stops
// partitioning and just sorts the remainder.
const selectSmallRange = 16

// samplePercentile returns the p-th percentile (nearest-rank method) of an
// already sorted slice.
func samplePercentile(sorted []uint64, p float64) uint64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[percentileRank(len(sorted), p)]
}

// percentileRank returns the 0-based index of the p-th percentile
// (nearest-rank method) in a sorted slice of length n > 0.
func percentileRank(n int, p float64) int {
	if p <= 0 {
		return 0
	}
	if p >= 1 {
		return n - 1
	}
	rank := int(math.Ceil(p*float64(n))) - 1
	return min(max(rank, 0), n-1)
}

// latencyPercentiles returns p50, p95 and p99 of samples, reordering samples
// in place. The values are exactly those of samplePercentile on the sorted
// slice, but found with three nested selections (p99 on the whole slice, then
// p95 and p50 on the shrinking prefix left of it) instead of a full sort,
// which is several times cheaper for a 10k-sample reservoir.
func latencyPercentiles(samples []uint64) (p50, p95, p99 uint64) {
	n := len(samples)
	if n == 0 {
		return 0, 0, 0
	}
	r50, r95, r99 := percentileRank(n, 0.50), percentileRank(n, 0.95), percentileRank(n, 0.99)

	// After selectNth(s, k) every element of s[:k] is <= s[k], so a lower
	// rank can be selected within that prefix. The prefix excludes s[k]
	// itself so the next selection cannot move the value already found; an
	// equal rank (r50 <= r95 <= r99 always) needs no further selection.
	selectNth(samples, r99)
	if r95 < r99 {
		selectNth(samples[:r99], r95)
	}
	if r50 < r95 {
		selectNth(samples[:r95], r50)
	}
	return samples[r50], samples[r95], samples[r99]
}

// selectNth reorders s so that s[k] holds the value it would have if s were
// sorted, every element of s[:k] is <= s[k] and every element of s[k+1:] is
// >= s[k] (quickselect with a median-of-three pivot and three-way partition,
// so runs of equal latencies terminate quickly). If partitioning makes too
// little progress it falls back to sorting the remaining range, which bounds
// the worst case at O(n log n).
func selectNth(s []uint64, k int) {
	lo, hi := 0, len(s)
	budget := 2 * bits.Len(uint(len(s)))
	for hi-lo > selectSmallRange {
		if budget == 0 {
			break
		}
		budget--
		lt, gt := partition3(s[lo:hi], medianOfThree(s[lo], s[lo+(hi-lo)/2], s[hi-1]))
		lt, gt = lt+lo, gt+lo
		switch {
		case k < lt:
			hi = lt
		case k >= gt:
			lo = gt
		default:
			return // s[k] lies within the run equal to the pivot
		}
	}
	slices.Sort(s[lo:hi])
}

// partition3 reorders s into three runs: s[:lt] < pivot, s[lt:gt] == pivot
// and s[gt:] > pivot (Dijkstra's Dutch national flag partition).
func partition3(s []uint64, pivot uint64) (lt, gt int) {
	lt, i, gt := 0, 0, len(s)
	for i < gt {
		switch v := s[i]; {
		case v < pivot:
			s[lt], s[i] = s[i], s[lt]
			lt++
			i++
		case v > pivot:
			gt--
			s[i], s[gt] = s[gt], s[i]
		default:
			i++
		}
	}
	return lt, gt
}

func medianOfThree(a, b, c uint64) uint64 {
	if a > b {
		a, b = b, a
	}
	if b > c {
		b = c
	}
	return max(a, b)
}
