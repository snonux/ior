package common

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// Task vp2: ansi.Truncate counted an ASCII base followed by U+FE0F / U+20E3
// as one cell while ansi.StringWidth (and the terminal) count the cluster as
// two, so FitRight and friends returned results one cell too wide per such
// cluster. These tests check the helpers against a reference model that does
// not use ansi at all: strings are built from units whose display width is
// known by construction, so the expected width and the expected cut are
// derived from the units, never from the code under test.

// unit is one grapheme cluster with its display width known by construction.
type unit struct {
	text  string
	width int
}

// clusterUnits lists the clusters the truncation helpers must treat as
// indivisible, grouped by the kind of bug they exposed or could expose.
var clusterUnits = []unit{
	// Plain cells.
	{"a", 1}, {"Z", 1}, {"/", 1}, {" ", 1}, {"é", 1}, {"e\u0301", 1},
	// Two-cell CJK and emoji, incl. a skin-tone modifier sequence.
	{"日", 2}, {"👍", 2}, {"👍🏽", 2},
	// ASCII + U+FE0F and keycap clusters: the ansi.Truncate undercount.
	{"1\ufe0f", 2}, {"a\ufe0f", 2}, {"1\ufe0f\u20e3", 2}, {"#\ufe0f\u20e3", 2},
	{"*\ufe0f\u20e3", 2},
	// A text-presentation emoji with U+FE0F, a ZWJ sequence, a flag.
	{"❤\ufe0f", 2}, {"👨\u200d👩\u200d👧", 2}, {"🏳\ufe0f\u200d🌈", 2}, {"🇩🇪", 2}, {"🇫🇷", 2},
}

// unitsString joins units into one string.
func unitsString(us []unit) string {
	var b strings.Builder
	for _, u := range us {
		b.WriteString(u.text)
	}
	return b.String()
}

// unitsWidth is the reference display width of us.
func unitsWidth(us []unit) int {
	w := 0
	for _, u := range us {
		w += u.width
	}
	return w
}

// refPrefix returns the longest whole-unit prefix of us that fits width.
func refPrefix(us []unit, width int) []unit {
	w := 0
	for i, u := range us {
		if w+u.width > width {
			return us[:i]
		}
		w += u.width
	}
	return us
}

// refSuffix returns the longest whole-unit suffix of us that fits width.
func refSuffix(us []unit, width int) []unit {
	w := 0
	for i := len(us) - 1; i >= 0; i-- {
		if w+us[i].width > width {
			return us[i+1:]
		}
		w += us[i].width
	}
	return us
}

// refTruncateRight is the reference for TruncateRight: the marker rule of
// truncate.go applied to whole units.
func refTruncateRight(us []unit, width int, tail string) string {
	if width <= 0 {
		return ""
	}
	if unitsWidth(us) <= width {
		return unitsString(us)
	}
	tw := DisplayWidth(tail) // the markers used here are plain text
	if tw < width {
		return unitsString(refPrefix(us, width-tw)) + tail
	}
	cut := unitsString(refPrefix(us, width))
	if cut == "" && tw <= width {
		return tail
	}
	return cut
}

// randomUnits builds 0..9 random units.
func randomUnits(rng *rand.Rand) []unit {
	us := make([]unit, rng.IntN(10))
	for i := range us {
		us[i] = clusterUnits[rng.IntN(len(clusterUnits))]
	}
	return us
}

// TestClusterUnitWidthsAgreeWithMeasure pins the premise of the reference
// model: DisplayWidth (ansi.StringWidth) and the by-construction widths agree
// for every unit, alone and in pairs.
func TestClusterUnitWidthsAgreeWithMeasure(t *testing.T) {
	for _, a := range clusterUnits {
		if got := DisplayWidth(a.text); got != a.width {
			t.Errorf("DisplayWidth(%q) = %d, want %d", a.text, got, a.width)
		}
		for _, b := range clusterUnits {
			if got, want := DisplayWidth(a.text+b.text), a.width+b.width; got != want {
				t.Errorf("DisplayWidth(%q) = %d, want %d", a.text+b.text, got, want)
			}
		}
	}
}

// TestTruncateRightClusterReference compares TruncateRight and FitRight with
// the reference for random cluster strings, every width and three markers.
func TestTruncateRightClusterReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 2026))
	for range 2000 {
		us := randomUnits(rng)
		s := unitsString(us)
		for width := -1; width <= 14; width++ {
			for _, marker := range []string{"", Ellipsis, ASCIIEllipsis} {
				want := refTruncateRight(us, width, marker)
				if got := TruncateRight(s, width, marker); got != want {
					t.Fatalf("TruncateRight(%q, %d, %q) = %q, want %q", s, width, marker, got, want)
				}
				if width > 0 {
					fit := FitRight(s, width, marker)
					if got := DisplayWidth(fit); got != width {
						t.Fatalf("FitRight(%q, %d, %q) = %q is %d cells wide", s, width, marker, fit, got)
					}
					if !strings.HasPrefix(fit, want) {
						t.Fatalf("FitRight(%q, %d, %q) = %q does not start with %q", s, width, marker, fit, want)
					}
				}
			}
		}
	}
}

// TestTruncateLeftMiddleClusterReference checks the suffix and both-ends
// helpers never split a cluster and keep the maximal whole-unit piece.
func TestTruncateLeftMiddleClusterReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 2026))
	for range 2000 {
		us := randomUnits(rng)
		s := unitsString(us)
		for width := 1; width <= 14; width++ {
			if unitsWidth(us) <= width {
				continue
			}
			checkLeftClusters(t, us, s, width)
			checkMiddleClusters(t, us, s, width)
		}
	}
}

// checkLeftClusters asserts TruncateLeft(s, width, "…") is the marker plus
// the maximal whole-unit suffix (or a hard cut when the marker has no room).
func checkLeftClusters(t *testing.T, us []unit, s string, width int) {
	t.Helper()
	got := TruncateLeft(s, width, Ellipsis)
	want := unitsString(refSuffix(us, width))
	if width > 1 {
		want = Ellipsis + unitsString(refSuffix(us, width-1))
	} else if want == "" {
		want = Ellipsis
	}
	if got != want {
		t.Fatalf("TruncateLeft(%q, %d) = %q, want %q", s, width, got, want)
	}
}

// checkMiddleClusters asserts TruncateMiddle(s, width, "…") keeps a
// whole-unit head of (width-1)/2 cells and the maximal whole-unit tail of the
// rest, and is never wider than width.
func checkMiddleClusters(t *testing.T, us []unit, s string, width int) {
	t.Helper()
	got := TruncateMiddle(s, width, Ellipsis)
	if width == 1 {
		if want := refTruncateRight(us, 1, Ellipsis); got != want {
			t.Fatalf("TruncateMiddle(%q, 1) = %q, want %q", s, got, want)
		}
		return
	}
	head := refPrefix(us, (width-1)/2)
	want := unitsString(head) + Ellipsis + unitsString(refSuffix(us, width-1-unitsWidth(head)))
	if got != want {
		t.Fatalf("TruncateMiddle(%q, %d) = %q, want %q", s, width, got, want)
	}
	if w := DisplayWidth(got); w > width {
		t.Fatalf("TruncateMiddle(%q, %d) = %q is %d cells wide", s, width, got, w)
	}
}

// TestKeycapAndFE0FRegressions pins the reviewer's probes and their
// neighbours with literal expectations.
func TestKeycapAndFE0FRegressions(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		width  int
		marker string
		want   string
	}{
		// Was "1\ufe0f\u20e3…" (3 cells) for width 2.
		{"keycap then ascii", "1\ufe0f\u20e3abc", 2, Ellipsis, "…"},
		{"keycap then ascii roomy", "1\ufe0f\u20e3abc", 4, Ellipsis, "1\ufe0f\u20e3a…"},
		// Was 2 cells for width 1: the keycap cannot be halved, so the
		// marker stands in for it (marker rule: never blank a value).
		{"lone keycap width one", "#\ufe0f\u20e3", 1, Ellipsis, "…"},
		{"keycap wider than marker room", "#\ufe0f\u20e3x", 1, Ellipsis, "…"},
		{"ascii fe0f fits exactly", "a\ufe0fb", 3, ASCIIEllipsis, "a\ufe0fb"},
		{"ascii fe0f cut", "a\ufe0fbcd", 3, Ellipsis, "a\ufe0f…"},
		{"three keycaps", strings.Repeat("1\ufe0f\u20e3", 3), 5, Ellipsis, "1\ufe0f\u20e31\ufe0f\u20e3…"},
		{"zwj family intact", "👨\u200d👩\u200d👧xyz", 3, "", "👨\u200d👩\u200d👧x"},
		{"flags intact", "🇩🇪🇫🇷🇯🇵", 5, Ellipsis, "🇩🇪🇫🇷…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TruncateRight(tc.in, tc.width, tc.marker)
			if got != tc.want {
				t.Fatalf("TruncateRight(%q, %d, %q) = %q, want %q", tc.in, tc.width, tc.marker, got, tc.want)
			}
			if w := DisplayWidth(got); w > tc.width {
				t.Fatalf("result %q is %d cells wide, limit %d", got, w, tc.width)
			}
			if fit := FitRight(tc.in, tc.width, tc.marker); DisplayWidth(fit) != tc.width {
				t.Fatalf("FitRight(%q, %d) = %q is %d cells wide", tc.in, tc.width, fit, DisplayWidth(fit))
			}
		})
	}
}

// TestPlainCutsAreUnchangedByTheClusterFix is the negative test: text with no
// miscounted cluster (ASCII, CJK, combining marks, skin-tone emoji) must cut
// exactly as before, so the re-measuring loop changes nothing for it.
func TestPlainCutsAreUnchangedByTheClusterFix(t *testing.T) {
	for _, s := range []string{"日本語abc", "éééé", "👍🏽👍🏽x", "ab日cd", "a\u0301bcd"} {
		for width := 1; width < DisplayWidth(s); width++ {
			if got := prefix(s, false, width); DisplayWidth(got) > width {
				t.Fatalf("prefix(%q, %d) = %q is too wide", s, width, got)
			}
			// Maximal: adding the next cluster would overflow, so one more
			// cell of budget can only add at most what fits.
			if more := prefix(s, false, width+1); DisplayWidth(more) > width+1 {
				t.Fatalf("prefix(%q, %d) = %q is too wide", s, width+1, more)
			}
		}
	}
}
