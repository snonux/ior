package eventstream

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// Regression for task vp2: the width helpers used to undercount an ASCII base
// followed by U+FE0F / U+20E3 (a keycap) by one cell per cluster, so a filter
// stack label or status message with keycaps produced lines wider than the
// terminal (a 43-cell panel at width 40, a width+1 status line at widths
// 20-33) that wrap and scroll the view.

// keycapLabel is a run of keycap clusters followed by plain text, the shape
// the reviewer used for the probes (three keycaps widened the panel).
var keycapLabel = strings.Repeat("1️⃣", 3) + "-report " + strings.Repeat("#️⃣", 4) + strings.Repeat("x", 20)

func TestRenderPanelKeepsKeycapStackWithinWidth(t *testing.T) {
	events := narrowTestEvents()
	for width := 1; width <= 160; width++ {
		out := RenderStreamTable(width, false, 10, 10, 10, 1000, Filter{}, []string{keycapLabel, "fd=20"}, events, -1, -1)
		// border top + status + filter + stack + header + rows + border bottom; a
		// wrapped line would add one, a widened panel trips the width check.
		assertPanelFits(t, width, out, 5+len(events)+1)
	}
}

// TestRenderPanelStackKeepsTheKeycapsItCanFit checks the cut is not merely
// narrow enough but also keeps whole leading clusters: at a generous width the
// keycap label survives intact.
func TestRenderPanelStackKeepsTheKeycapsItCanFit(t *testing.T) {
	out := RenderStreamTable(120, false, 10, 10, 10, 1000, Filter{}, []string{"1️⃣-report"}, narrowTestEvents(), -1, -1)
	if !strings.Contains(out, "1️⃣-report") {
		t.Fatalf("a keycap label that fits must be rendered whole:\n%s", out)
	}
}

func TestStatusLineWithKeycapsFitsWidth(t *testing.T) {
	for width := 10; width <= 60; width++ {
		m := newFooterTestModel(t)
		m.SetStatusMessage(keycapLabel)
		out := m.View(width, 24)
		last := out[strings.LastIndex(out, "\n")+1:]
		if w := lipgloss.Width(last); w > width {
			t.Fatalf("width %d: status line is %d cells wide: %q", width, w, last)
		}
	}
}

// TestRenderPanelStillCutsPlainOverflow is the negative check: the helper swap
// must not stop plain (keycap-free) long lines from being cut to the width.
func TestRenderPanelStillCutsPlainOverflow(t *testing.T) {
	events := narrowTestEvents()
	out := RenderStreamTable(40, false, 10, 10, 10, 1000, Filter{}, []string{strings.Repeat("comm~x", 30)}, events, -1, -1)
	assertPanelFits(t, 40, out, 5+len(events)+1)
}
