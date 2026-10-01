package dashboard

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Task iz2: with the help bar off and the stream live the Stream tab drew no
// footer at all, so "Export failed", "Open failed", "Invalid regex" and
// "No match" were set but never shown. Through the whole dashboard frame, at
// heights 1..30, widths 20..200, help on/off, live/paused and with/without a
// message, the frame keeps the height matrix's contract (assertFrameFits: tab
// bar first, the stream's own output, the status line last, nothing wider
// than the terminal) and the message is on screen exactly when the stream
// body has a row beyond its 6-row panel.
func TestStreamStatusMessageReachesTheFrame(t *testing.T) {
	const message = "Export failed: open /nonexistent/out.csv: no such file or directory"
	for _, help := range []bool{false, true} {
		for _, paused := range []bool{false, true} {
			for _, msg := range []string{"", message} {
				c := fitCase{tab: TabStream, paused: paused}
				// Independent models per cell: parallel keeps -race affordable.
				t.Run(fmt.Sprintf("help=%v/paused=%v/msg=%v", help, paused, msg != ""), func(t *testing.T) {
					t.Parallel()
					checkStreamMessageFrames(t, c, help, msg)
				})
			}
		}
	}
}

// checkStreamMessageFrames runs one cell of
// TestStreamStatusMessageReachesTheFrame over every width and height.
func checkStreamMessageFrames(t *testing.T, c fitCase, help bool, msg string) {
	t.Helper()
	for width := 20; width <= 200; width += 30 {
		for height := 1; height <= 30; height++ {
			label := fmt.Sprintf("help=%v paused=%v msg=%v %dx%d", help, c.paused, msg != "", width, height)
			m := newFitModel(t, c, help, width, height)
			m.streamModel.SetStatusMessage(msg)
			assertFrameFits(t, m, c, label, width, height)
			body := splitFrameRows(height, lipgloss.Height(m.renderStatusBlock(width))).body
			shown := strings.Contains(m.View().Content, "Export failed")
			if want := msg != "" && body > streamTableMinRows; shown != want {
				t.Fatalf("%s: message shown = %v, want %v (body %d rows):\n%s", label, shown, want, body, m.View().Content)
			}
		}
	}
}

// End to end through the keys with the help bar off: a search pauses the
// stream, so an invalid pattern or a missed search shows its message under
// the paused footer; space then resumes the live stream, which keeps the
// message (it is cleared by the next modal key or replaced by the next
// export or search, as before) but used to drop the footer and with it the
// message. It must stay on screen while live.
func TestStreamSearchErrorsStayShownWhenResumedWithHelpOff(t *testing.T) {
	for _, tc := range []struct{ pattern, want string }{
		{"[a", "Invalid regex"},
		{"zzz-no-such-row", "No match"},
	} {
		m := newFitModel(t, fitCase{tab: TabStream}, false, 100, 24)
		m = pressStreamKey(t, m, '/')
		for _, r := range tc.pattern {
			m = pressStreamKey(t, m, r)
		}
		next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
		m = next.(*Model)
		if out := m.View().Content; !m.streamModel.Paused() || !strings.Contains(out, tc.want) {
			t.Fatalf("pattern %q: want %q on the paused stream:\n%s", tc.pattern, tc.want, out)
		}
		m = pressStreamKey(t, m, ' ')
		if m.streamModel.Paused() {
			t.Fatalf("pattern %q: space did not resume the stream", tc.pattern)
		}
		if out := m.View().Content; !strings.Contains(out, tc.want) {
			t.Fatalf("pattern %q: %q gone once live with help off:\n%s", tc.pattern, tc.want, out)
		}
		// Clearing is unchanged: a key into the search modal drops it (here
		// Esc, which also closes the modal so the stream is drawn again).
		m = pressStreamKey(t, m, '/')
		next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
		m = next.(*Model)
		if out := m.View().Content; m.streamModel.SearchModalVisible() || strings.Contains(out, tc.want) {
			t.Fatalf("pattern %q: %q survives a key into the search modal:\n%s", tc.pattern, tc.want, out)
		}
	}
}
