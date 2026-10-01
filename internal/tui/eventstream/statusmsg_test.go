package eventstream

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/tui/common"
)

// statusMessageCases are the stream's error and search messages (task iz2):
// the ways a failed export or open, a bad regex or a missed search reach the
// user. The last one mixes wide runes, an escape and a newline, so the line
// must be sanitised and cut by display cells.
var statusMessageCases = []string{
	"Export failed: open /nonexistent/out.csv: no such file or directory",
	"Open failed: exec: \"vi\": executable file not found in $PATH",
	"Invalid regex: error parsing regexp: missing closing ]: `[a`",
	`No match: "needle"`,
	"Export failed: /tmp/日本語\x1b[8m/" + strings.Repeat("very-long-dir/", 12) + "out.csv\nsecond line",
}

// Regression for task iz2: with the dashboard help bar off and the stream
// live, View drew no footer at all, so a status message ("Export failed",
// "Invalid regex", "No match") was set but never shown. The message now takes
// the first row the table leaves free whatever the help bar and pause state.
func TestStatusMessageShownWithHelpOffWhileLive(t *testing.T) {
	m := newFooterTestModel(t)
	m.SetFooterVisible(false)
	m.SetStatusMessage("Export failed: no such directory")
	for height := 7; height <= 30; height++ {
		out := m.View(100, height)
		lines := strings.Split(out, "\n")
		if last := lines[len(lines)-1]; last != "Export failed: no such directory" {
			t.Fatalf("height %d: last line %q, want the status message:\n%s", height, last, out)
		}
		if strings.Contains(out, "Row ") {
			t.Fatalf("height %d: live help-off view shows the Row footer:\n%s", height, out)
		}
	}
}

// TestStatusMessageMatrix holds the stream view to its budget over heights
// 6..30, widths 20..200, help on/off, live/paused and message present/absent:
// it never outgrows height or width, a message is the last line whenever the
// table leaves a row free (from 7 rows; at 6 the panel alone fills the view),
// cut to the width and never wrapped, and the Row/Sel footer keeps its old
// rule (help bar on or paused) and yields its row to the message first.
func TestStatusMessageMatrix(t *testing.T) {
	for _, message := range append([]string{""}, statusMessageCases...) {
		for _, help := range []bool{false, true} {
			for _, paused := range []bool{false, true} {
				label := fmt.Sprintf("message %q help %v paused %v", message, help, paused)
				// The cells are independent models; running them in parallel
				// keeps the matrix affordable under -race.
				t.Run(label, func(t *testing.T) {
					t.Parallel()
					m := newFooterTestModel(t)
					m.SetFooterVisible(help)
					if paused {
						m.HandleKey(" ")
					}
					m.SetStatusMessage(message)
					checkStatusMessageViews(t, &m, label, message, help || paused)
				})
			}
		}
	}
}

// checkStatusMessageViews runs one matrix cell over every width and height.
func checkStatusMessageViews(t *testing.T, m *Model, label, message string, footer bool) {
	t.Helper()
	for width := 20; width <= 200; width += 15 {
		want := common.TruncateRight(common.Sanitize(message), width, footerTail)
		for height := 6; height <= 30; height++ {
			out := m.View(width, height)
			assertViewFits(t, fmt.Sprintf("%s height %d", label, height), width, height, out)
			lines := strings.Split(out, "\n")
			last := lines[len(lines)-1]
			shown := message != "" && height >= 7
			// The dashboard draws the message in its status line exactly when
			// the panel has no row for it (task 403).
			if got := m.UndrawnStatusMessage() != ""; got != (message != "" && !shown) {
				t.Fatalf("%s %dx%d: UndrawnStatusMessage non-empty = %v, want %v", label, width, height, got, message != "" && !shown)
			}
			if got := last == want && message != ""; got != shown {
				t.Fatalf("%s %dx%d: message shown = %v, want %v (last line %q)", label, width, height, got, shown, last)
			}
			// The model has a filter stack: at 7 rows its line takes the one
			// spare row (the message outranks it), so Row/Sel needs 8 rows
			// alone and 9 beside a message.
			rowSel := footer && (message == "" && height >= 8 || height >= 9)
			if got := strings.Contains(out, "\nRow ") || strings.Contains(out, "\nSel "); got != rowSel {
				t.Fatalf("%s %dx%d: Row/Sel shown = %v, want %v:\n%s", label, width, height, got, rowSel, out)
			}
		}
	}
}
