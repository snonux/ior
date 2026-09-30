package statsengine

import (
	"hash/fnv"
	"math"
	"testing"
)

// splitmix64 is a fixed, well-mixed 64-bit hash. The sketch tests use it
// (instead of the ranker's randomly seeded maphash) so every run sees the
// same hashes and a failure is reproducible.
func splitmix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

// seededPathHash is the deterministic stand-in for the ranker's path hash:
// FNV-1a of the path, mixed with a per-seed constant through splitmix64.
func seededPathHash(seed uint64) func(string) uint64 {
	return func(path string) uint64 {
		h := fnv.New64a()
		_, _ = h.Write([]byte(path))
		return splitmix64(h.Sum64() ^ splitmix64(seed))
	}
}

func TestFileSketchExactBelowKAndBoundedAbove(t *testing.T) {
	s := newFileSketch(64)
	for i := uint64(0); i < 40; i++ {
		s.Add(splitmix64(i))
		s.Add(splitmix64(i)) // re-adding is idempotent
	}
	if got := s.Estimate(); got != 40 {
		t.Fatalf("Estimate below k = %d, want exactly 40", got)
	}

	big := newFileSketch(256)
	for i := uint64(1); i <= 20000; i++ {
		big.Add(splitmix64(i))
	}
	if len(big.hashes) != 256 {
		t.Fatalf("sketch holds %d hashes, want k=256", len(big.hashes))
	}
}

// TestFileSketchEstimatorFormula pins the estimator itself with a hand-made
// sketch, independent of any hash quality: k=4 hashes whose 4th smallest is
// exactly half of the 2^64 range must estimate (k-1)/0.5 = 6 distinct
// values. An off-by-one (k instead of k-1) or an added constant changes it.
func TestFileSketchEstimatorFormula(t *testing.T) {
	s := newFileSketch(4)
	for _, h := range []uint64{1, 2, 3, 1 << 63} {
		s.Add(h)
	}
	if got := s.Estimate(); got != 6 {
		t.Fatalf("Estimate = %d, want (k-1)/0.5 = 6", got)
	}

	// A quarter of the range: 3 / 0.25 = 12.
	q := newFileSketch(4)
	for _, h := range []uint64{1, 2, 3, 1 << 62} {
		q.Add(h)
	}
	if got := q.Estimate(); got != 12 {
		t.Fatalf("Estimate = %d, want (k-1)/0.25 = 12", got)
	}
}

// sketchErrors returns the relative estimation error of a k=256 sketch over
// n distinct items for each of `seeds` fixed seeds.
func sketchErrors(n, seeds int) []float64 {
	errs := make([]float64, 0, seeds)
	for seed := 0; seed < seeds; seed++ {
		s := newFileSketch(dirFileSketchSize)
		for i := 0; i < n; i++ {
			s.Add(splitmix64(splitmix64(uint64(seed)) ^ uint64(i)))
		}
		errs = append(errs, (float64(s.Estimate())-float64(n))/float64(n))
	}
	return errs
}

// TestFileSketchIsUnbiasedWithTheDocumentedError averages the estimator over
// 400 fixed seeds. Theory for k=256: the (k-1)/kth estimator is unbiased and
// its relative standard error is 1/sqrt(k-2) = 6.3%; the mean over 400 seeds
// therefore lands within about 0.3% of zero. A biased estimator (k/kth is
// +0.4%, (k+40)/kth is +16%) or a wrong error claim fails these bounds.
func TestFileSketchIsUnbiasedWithTheDocumentedError(t *testing.T) {
	for _, n := range []int{1000, 10000} {
		errs := sketchErrors(n, 400)
		var sum, sumSq float64
		for _, e := range errs {
			sum += e
			sumSq += e * e
		}
		bias := sum / float64(len(errs))
		rmse := math.Sqrt(sumSq / float64(len(errs)))
		if math.Abs(bias) > 0.03 {
			t.Errorf("n=%d: mean relative error (bias) = %.4f, want |bias| < 3%%", n, bias)
		}
		if rmse < 0.04 || rmse > 0.10 {
			t.Errorf("n=%d: RMSE = %.4f, want about 6.3%% (within 4%%..10%%)", n, rmse)
		}
	}
}

// TestFileSketchFixedSeedIsDeterministic pins one fixed seed tightly: the
// estimate for a given hash sequence never changes between runs, and stays
// inside the +-3 sigma band (19%) around the truth.
func TestFileSketchFixedSeedIsDeterministic(t *testing.T) {
	const n = 10000
	first := sketchErrors(n, 1)[0]
	if again := sketchErrors(n, 1)[0]; again != first {
		t.Fatalf("same seed gave %v then %v", first, again)
	}
	if math.Abs(first) > 0.19 {
		t.Fatalf("seed 0 relative error %.4f exceeds 3 sigma", first)
	}
}
