package common

import (
	"strings"
	"testing"
)

// Task vp2 review: the cluster-aware cuts re-measure ansi.Truncate and
// ansi.TruncateLeft results because those functions count a keycap as one cell
// while StringWidth counts two. A long keycap-heavy string therefore has a
// large gap between the budget handed to the cut functions and the real width,
// and a linear walk over that gap (one full-string cut per step) made
// TruncateLeft and TruncateMiddle quadratic (about 32ms for a 4KB path of 580
// keycaps). These tests and benchmarks pin the logarithmic search that
// replaced the walk.

// keycapPath is a path-like string made of n keycap clusters (7 bytes each,
// two cells each) ending in a plain file name.
func keycapPath(n int) string {
	return "/srv/" + strings.Repeat("1️⃣", n) + "/file.txt"
}

// cutProbeBudget bounds the number of full-string ansi cuts one truncation
// call may make on a 600-keycap string. The binary searches need about
// log2(1200) + log2(width) probes (a few tens in total); the former one-cell
// walk made roughly 600 per call. Counting probes through cutProbeHook is
// deterministic, unlike a wall-clock bound, so the test cannot flake on a
// loaded machine.
const cutProbeBudget = 40

// countCutProbes runs f and returns how many full-string cuts it made.
// It sets the package-global cutProbeHook, so tests that call it must not use
// t.Parallel (the hook would race).
func countCutProbes(t *testing.T, f func()) int {
	t.Helper()
	n := 0
	cutProbeHook = func() { n++ }
	t.Cleanup(func() { cutProbeHook = nil })
	f()
	return n
}

func TestKeycapHeavyCutsStayCheap(t *testing.T) {
	s := keycapPath(600)
	cuts := map[string]func() string{
		"TruncateRight30":  func() string { return TruncateRight(s, 30, Ellipsis) },
		"TruncateRight120": func() string { return TruncateRight(s, 120, ASCIIEllipsis) },
		"TruncateLeft30":   func() string { return TruncateLeft(s, 30, Ellipsis) },
		"TruncateLeft120":  func() string { return TruncateLeft(s, 120, ASCIIEllipsis) },
		"TruncateMiddle30": func() string { return TruncateMiddle(s, 30, Ellipsis) },
		"FitRight120":      func() string { return FitRight(s, 120, Ellipsis) },
	}
	for name, cut := range cuts {
		t.Run(name, func(t *testing.T) {
			probes := countCutProbes(t, func() { _ = cut() })
			t.Logf("%s: %d full-string cuts", name, probes)
			if probes > cutProbeBudget {
				t.Fatalf("%s on a 600-keycap string made %d full-string cuts, budget %d (linear walk?)", name, probes, cutProbeBudget)
			}
		})
	}
}

// TestKeycapHeavyCutsAreCorrect checks the logarithmic search returns the same
// pieces the reference model derives, on a string long enough that the search
// takes many steps.
func TestKeycapHeavyCutsAreCorrect(t *testing.T) {
	us := []unit{{"/", 1}}
	for range 600 {
		us = append(us, unit{"1️⃣", 2})
	}
	us = append(us, unit{"x", 1}, unit{"y", 1})
	s := unitsString(us)
	for _, width := range []int{1, 2, 3, 4, 5, 29, 30, 31, 120, 121, 1199, 1200, 1201} {
		if got, want := TruncateRight(s, width, Ellipsis), refTruncateRight(us, width, Ellipsis); got != want {
			t.Fatalf("TruncateRight width %d: got %d bytes, want %d bytes", width, len(got), len(want))
		}
		checkLeftClusters(t, us, s, width)
		checkMiddleClusters(t, us, s, width)
	}
}

func benchmarkKeycapCut(b *testing.B, cut func(string) string) {
	s := keycapPath(600)
	b.ReportAllocs()
	for b.Loop() {
		_ = cut(s)
	}
}

func BenchmarkTruncateLeftKeycaps(b *testing.B) {
	benchmarkKeycapCut(b, func(s string) string { return TruncateLeft(s, 30, Ellipsis) })
}

func BenchmarkTruncateMiddleKeycaps(b *testing.B) {
	benchmarkKeycapCut(b, func(s string) string { return TruncateMiddle(s, 30, Ellipsis) })
}

func BenchmarkTruncateRightKeycaps(b *testing.B) {
	benchmarkKeycapCut(b, func(s string) string { return TruncateRight(s, 120, Ellipsis) })
}
