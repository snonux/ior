package statsengine

import "slices"

// fileSketch counts distinct 64-bit hashes in bounded memory: a k-minimum-
// values sketch. It keeps the k smallest distinct hashes seen. While fewer
// than k distinct hashes have been seen the count is exact; afterwards the
// k-th smallest hash h (as a fraction of the 2^64 hash range) estimates the
// count as (k-1)/h, with a relative standard error near 1/sqrt(k-2).
//
// It exists so a directory row can show "Files" without remembering every
// file name of a directory that may hold millions of them.
type fileSketch struct {
	k      int
	hashes []uint64 // ascending, distinct, at most k
}

func newFileSketch(k int) fileSketch {
	return fileSketch{k: k}
}

// Add records one file's hash. Re-adding a known hash, or one larger than
// the k-th smallest once the sketch is full, changes nothing; both cases
// (the hot path for repeated accesses) cost one binary search.
func (s *fileSketch) Add(h uint64) {
	idx, found := slices.BinarySearch(s.hashes, h)
	if found {
		return
	}
	if len(s.hashes) >= s.k {
		if idx >= s.k {
			return
		}
		// Full: drop the largest to make room for the smaller newcomer.
		s.hashes = s.hashes[:s.k-1]
	}
	s.hashes = slices.Insert(s.hashes, idx, h)
}

// Estimate returns the distinct-hash count: exact below k, estimated at k.
func (s *fileSketch) Estimate() uint64 {
	if len(s.hashes) < s.k {
		return uint64(len(s.hashes))
	}
	kth := float64(s.hashes[s.k-1]) / (1 << 64)
	if kth <= 0 {
		return uint64(s.k)
	}
	return max(uint64(s.k), uint64(float64(s.k-1)/kth+0.5))
}
