package dashboard

import (
	"strings"
	"testing"

	"ior/internal/tui/common"
)

// Regression for task vp2: truncateText (Processes Comm column) and
// truncatePlain (tab bar / filter strings) delegate to common.TruncateRight,
// which used to return results one cell too wide per ASCII+U+FE0F / keycap
// cluster, misaligning every column to the right of a traced comm name.
func TestTruncateHelpersKeepKeycapNamesWithinLimit(t *testing.T) {
	names := []string{
		"1️⃣-report",
		strings.Repeat("#️⃣", 5) + "tail",
		"a️worker-thread",
	}
	for _, name := range names {
		for limit := 1; limit <= 20; limit++ {
			if got := truncateText(name, limit); common.DisplayWidth(got) > limit {
				t.Fatalf("truncateText(%q, %d) = %q is %d cells wide", name, limit, got, common.DisplayWidth(got))
			}
			if got := truncatePlain(name, limit); common.DisplayWidth(got) > limit {
				t.Fatalf("truncatePlain(%q, %d) = %q is %d cells wide", name, limit, got, common.DisplayWidth(got))
			}
		}
	}
}

// TestTruncateTextKeepsWholeKeycapWhenItFits is the negative check: a keycap
// that fits the limit is kept, not dropped along with the overflow.
func TestTruncateTextKeepsWholeKeycapWhenItFits(t *testing.T) {
	if got, want := truncateText("1️⃣-report-worker", 8), "1️⃣-re..."; got != want {
		t.Fatalf("truncateText = %q, want %q", got, want)
	}
	if got := truncateText("1️⃣ab", 4); got != "1️⃣ab" {
		t.Fatalf("a value that fits must be returned unchanged, got %q", got)
	}
}
