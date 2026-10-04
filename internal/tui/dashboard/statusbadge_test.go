package dashboard

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/streamrow"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// warningRing returns a stream ring buffer holding normal rows interleaved
// with the given number of synthetic warning rows, the state a run with a
// wrong -tid or zero attached probes leaves behind.
func warningRing(warnings int) *eventstream.RingBuffer {
	rb := eventstream.NewRingBuffer()
	seq := uint64(0)
	for i := range 50 {
		seq++
		rb.Push(eventstream.StreamEvent{Seq: seq, Syscall: "read", Comm: "proc", PID: 1234})
		if i < warnings {
			seq++
			rb.Push(streamrow.NewWarning(seq, fmt.Sprintf("warning %d", i)))
		}
	}
	return rb
}

// badgeModel builds a dashboard on tab at width x height over a stream
// holding the given number of warning rows.
func badgeModel(t *testing.T, tab Tab, warnings, width, height int, help bool) *Model {
	t.Helper()
	m := newFitModel(t, fitCase{tab: tab, mode: lookupTab(tab).AllowedVizModes[0]}, help, width, height)
	m.SetStreamSource(warningRing(warnings))
	m.streamModel.Refresh()
	return m
}

// statusLine is the last line of m's frame, without styling and padding.
func statusLine(m *Model) string {
	lines := strings.Split(m.View().Content, "\n")
	return plainLine(lines[len(lines)-1])
}

// hasAnyBadge reports whether line carries any rendering of a warning badge
// for count warnings, or the word "warn" that starts the longer ones (the
// summary of these tests never contains it).
func hasAnyBadge(line string, count int) bool {
	for _, badge := range warningBadges(count) {
		if strings.Contains(line, badge) {
			return true
		}
	}
	return strings.Contains(line, "warn")
}

// TestWarningBadgesNameTheStreamTab pins the badge texts: nothing without
// warnings, and every rendering carrying the count, the longer ones the
// Stream tab's number (looked up in the registry) and name.
func TestWarningBadgesNameTheStreamTab(t *testing.T) {
	for _, count := range []int{-1, 0} {
		if got := warningBadges(count); got != nil {
			t.Fatalf("warningBadges(%d) = %q, want nil", count, got)
		}
	}
	number := tabIndex(TabStream, orderedTabs()) + 1
	want := []string{
		fmt.Sprintf("warnings: 3 (%d:Stream)", number),
		fmt.Sprintf("warn: 3 (%d)", number),
		"!3",
	}
	got := warningBadges(3)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("warningBadges(3) = %q, want %q", got, want)
	}
	for i := 1; i < len(got); i++ {
		if common.DisplayWidth(got[i]) >= common.DisplayWidth(got[i-1]) {
			t.Fatalf("badge renderings must get shorter: %q", got)
		}
	}
}

// TestFitStatusRowKeepsThePriorities sweeps the row at widths 1..200 and
// checks the order in which it gives way: never wider than the width, the
// summary always kept (only cut to the width), the badge in its longest
// rendering that fits beside the summary - dropped before the summary loses
// a cell - and the help text only in what is left.
func TestFitStatusRowKeepsThePriorities(t *testing.T) {
	const help = "press H for help"
	const summary = "filter: none | auto-reset: off"
	badges := warningBadges(12)
	sumWidth := common.DisplayWidth(summary)
	for width := 1; width <= 200; width++ {
		row := fitStatusRow(help, statusTail{badges: badges, summary: summary}, width)
		out := row.plain()
		if w := common.DisplayWidth(out); w > width {
			t.Fatalf("width %d: row is %d cells: %q", width, w, out)
		}
		if row.summary != truncatePlain(summary, width) {
			t.Fatalf("width %d: summary %q, want it cut only to the width", width, row.summary)
		}
		if !strings.HasSuffix(out, row.summary) {
			t.Fatalf("width %d: summary is not the end of the row: %q", width, out)
		}
		room := width - sumWidth - common.DisplayWidth(statusSeparator)
		want := ""
		for _, badge := range badges {
			if common.DisplayWidth(badge) <= room {
				want = badge
				break
			}
		}
		if row.badge != want {
			t.Fatalf("width %d: badge %q, want %q (room %d)", width, row.badge, want, room)
		}
		if row.help != "" && !strings.HasPrefix(help, strings.TrimSuffix(row.help, common.Ellipsis)) {
			t.Fatalf("width %d: help %q is not a cut of %q", width, row.help, help)
		}
	}
	full := fitStatusRow(help, statusTail{badges: badges, summary: summary}, 200).plain()
	if wantFull := help + " | " + badges[0] + " | " + summary; full != wantFull {
		t.Fatalf("wide row = %q, want %q", full, wantFull)
	}
	if got := fitStatusRow(help, statusTail{badges: badges, summary: summary}, 0).plain(); got != full {
		t.Fatalf("unlimited row = %q, want %q", got, full)
	}
}

// TestFitStatusRowWithoutBadgeIsUnchanged pins that a row without warnings
// is exactly the help/summary row the dashboard drew before the badge.
func TestFitStatusRowWithoutBadgeIsUnchanged(t *testing.T) {
	const help, summary = "press H for help", "filter: none"
	cases := []struct {
		width int
		want  string
	}{
		{0, help + " | " + summary},
		{200, help + " | " + summary},
		{20, "pres… | " + summary},
		{14, summary},
		{5, truncatePlain(summary, 5)},
	}
	for _, c := range cases {
		row := fitStatusRow(help, statusTail{summary: summary}, c.width)
		if got := row.render(true); got != c.want {
			t.Fatalf("width %d: row = %q, want %q", c.width, got, c.want)
		}
	}
	if got := fitStatusRow(help, statusTail{}, 5).plain(); got != help {
		t.Fatalf("empty tail must leave the help text alone, got %q", got)
	}
}

// TestStatusBadgeShownOnEveryTabButStream pins where the badge appears: on
// every tab but the Stream tab, which already shows the warning rows.
func TestStatusBadgeShownOnEveryTabButStream(t *testing.T) {
	badge := warningBadges(2)[0]
	for _, tab := range orderedTabs() {
		for _, help := range []bool{false, true} {
			line := statusLine(badgeModel(t, tab, 2, 200, 40, help))
			if tab == TabStream {
				if hasAnyBadge(line, 2) {
					t.Fatalf("%s help=%v: badge on the Stream tab itself: %q", tab, help, line)
				}
				continue
			}
			if !strings.Contains(line, badge) {
				t.Fatalf("%s help=%v: expected %q in the status line, got %q", tab, help, badge, line)
			}
		}
	}
}

// TestStatusBadgeAbsentWithoutWarnings pins that a stream of normal rows
// leaves the status line without any badge.
func TestStatusBadgeAbsentWithoutWarnings(t *testing.T) {
	for _, tab := range orderedTabs() {
		if line := statusLine(badgeModel(t, tab, 0, 200, 40, false)); hasAnyBadge(line, 0) {
			t.Fatalf("%s: badge without warnings: %q", tab, line)
		}
	}
}

// TestStatusBadgeFollowsTheRing pins that the badge counts the warnings the
// ring holds right now: it grows with new warnings, shrinks as the ring
// wraps over old ones and disappears on a stream reset (trace restart).
func TestStatusBadgeFollowsTheRing(t *testing.T) {
	m := badgeModel(t, TabFlame, 0, 200, 40, false)
	rb := warningRing(2)
	m.SetStreamSource(rb)
	if line := statusLine(m); !strings.Contains(line, warningBadges(2)[0]) {
		t.Fatalf("expected two warnings, got %q", line)
	}
	rb.Push(streamrow.NewWarning(1000, "third"))
	if line := statusLine(m); !strings.Contains(line, warningBadges(3)[0]) {
		t.Fatalf("expected three warnings, got %q", line)
	}
	for i := range streamrow.RingBufferCapacity {
		rb.Push(eventstream.StreamEvent{Seq: uint64(2000 + i), Syscall: "read"})
	}
	if line := statusLine(m); hasAnyBadge(line, 3) {
		t.Fatalf("a lap of normal rows evicted every warning, badge still shown: %q", line)
	}
	rb.Push(streamrow.NewWarning(50000, "after the wrap"))
	if line := statusLine(m); !strings.Contains(line, warningBadges(1)[0]) {
		t.Fatalf("expected one warning, got %q", line)
	}
	rb.Reset()
	if line := statusLine(m); hasAnyBadge(line, 1) {
		t.Fatalf("badge survived the stream reset: %q", line)
	}
}

// TestStatusBadgeFitsEveryTerminal sweeps the frame with a badge at widths
// 1..200, several heights and help on/off, on the default Flame tab, a
// summary tab and the Stream tab. At every width the frame is no taller than
// the terminal and its last line is the status line, no wider than the
// terminal (assertStatusLineLast); from 20 columns the whole frame is held to
// the frame contract (assertFrameFits: tab bar first, body, status line last,
// no line wider than the terminal). Narrower, the Overview panels keep their
// own minimum width (TestSummaryTabsFitTheTerminalWidth sweeps them from 20
// too), which is not the status line's concern. Off the Stream tab the badge
// must appear in its longest rendering whenever the summary leaves room for
// it, and never when not even its shortest one fits.
func TestStatusBadgeFitsEveryTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("width x height sweep")
	}
	for _, tab := range []Tab{TabFlame, TabOverview, TabStream} {
		c := fitCase{tab: tab, mode: lookupTab(tab).AllowedVizModes[0]}
		for _, help := range []bool{false, true} {
			// One model per tab and help state, resized like the runtime
			// does: building a populated model per cell made the sweep slow.
			m := badgeModel(t, tab, 4, 80, 24, help)
			for _, height := range []int{1, 3, 24} {
				for width := 1; width <= 200; width++ {
					next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
					m = next.(*Model)
					label := fmt.Sprintf("%s help=%v %dx%d", tab, help, width, height)
					assertStatusLineLast(t, m, label, width, height)
					if width >= 20 {
						assertFrameFits(t, m, c, label, width, height)
					}
					assertBadgeShownWhenItFits(t, m, label, width)
				}
			}
		}
	}
}

// assertStatusLineLast checks that m's frame fits the terminal's height and
// ends with the status block's last line, which fits the terminal's width.
func assertStatusLineLast(t *testing.T, m *Model, label string, width, height int) {
	t.Helper()
	out := m.View().Content
	if got := lipgloss.Height(out); got > height {
		t.Fatalf("%s: View is %d lines, terminal has %d", label, got, height)
	}
	lines := strings.Split(out, "\n")
	last := plainLine(lines[len(lines)-1])
	if want := plainLine(clipTailLines(m.renderStatusBlock(width), 1)); last != want {
		t.Fatalf("%s: last line %q is not the status line %q", label, last, want)
	}
	if w := lipgloss.Width(last); w > width {
		t.Fatalf("%s: status line is %d cells wide: %q", label, w, last)
	}
}

// assertBadgeShownWhenItFits checks the badge in m's status line against the
// room its summary leaves at width.
func assertBadgeShownWhenItFits(t *testing.T, m *Model, label string, width int) {
	t.Helper()
	line := statusLine(m)
	badges := warningBadges(4)
	if m.activeTab == TabStream {
		if hasAnyBadge(line, 4) {
			t.Fatalf("%s: badge on the Stream tab: %q", label, line)
		}
		return
	}
	room := width - common.DisplayWidth(m.filterSummary()) - common.DisplayWidth(statusSeparator)
	fits := room >= common.DisplayWidth(badges[0])
	switch shown := strings.Contains(line, badges[0]); {
	case fits && !shown:
		t.Fatalf("%s: room %d for %q but the status line is %q", label, room, badges[0], line)
	case room < common.DisplayWidth(badges[len(badges)-1]) && hasAnyBadge(line, 4):
		t.Fatalf("%s: no room (%d) for a badge but the status line is %q", label, room, line)
	}
}

// TestStatusBadgeUsesTheWarningStyle pins the badge's colour in both themes
// and both status-row renderings (plain below 90 columns, the styled help bar
// from 90): it is drawn in ErrorStyle, the style of the warning rows in the
// Stream tab, and without the colour (a NO_COLOR terminal downsamples the
// SGR away) the row still reads the full badge text.
func TestStatusBadgeUsesTheWarningStyle(t *testing.T) {
	t.Cleanup(func() { common.ApplyPalette(true) })
	for _, dark := range []bool{true, false} {
		common.ApplyPalette(dark)
		badge := warningBadges(2)[0]
		styled := common.Current().ErrorStyle.Render(badge)
		for _, width := range []int{80, 120} {
			m := badgeModel(t, TabFlame, 2, width, 30, false)
			status := m.renderStatusBlock(width)
			label := fmt.Sprintf("dark=%v width=%d", dark, width)
			if !strings.Contains(status, styled) {
				t.Fatalf("%s: badge not in ErrorStyle: %q", label, status)
			}
			if !strings.Contains(ansi.Strip(status), badge) {
				t.Fatalf("%s: badge text lost without colour: %q", label, ansi.Strip(status))
			}
			if w := lipgloss.Width(status); w > width {
				t.Fatalf("%s: status is %d cells wide", label, w)
			}
		}
	}
}

// TestStatusBadgeResumesTheHelpBarColour pins that the text after the badge
// keeps the help bar's muted colour in the styled (>= 90 columns) row: the
// badge's own style ends in an SGR reset, which would otherwise leave the
// summary in the terminal's default colour.
func TestStatusBadgeResumesTheHelpBarColour(t *testing.T) {
	row := fitStatusRow("press H for help", statusTail{badges: warningBadges(1), summary: "filter: none"}, 120)
	muted := lipgloss.NewStyle().Foreground(common.Current().Muted).Render(" | filter: none")
	if out := row.render(true); !strings.HasSuffix(out, muted) {
		t.Fatalf("styled row does not resume the muted colour after the badge: %q", out)
	}
	if out := row.render(false); !strings.HasSuffix(out, " | filter: none") || strings.HasSuffix(out, muted) {
		t.Fatalf("plain row must leave the summary unstyled: %q", out)
	}
}

// TestStreamStatusMessageReachesTheStatusLineWhenThePanelHasNoRow (task 403):
// at the Stream tab's 6-row minimum body the panel fills the body and the
// footer, which is where a status message ("Export failed", "Invalid regex",
// "No match") is drawn, has no row. The message then goes into the status
// line's badge slot, which the Stream tab leaves free; with a spare row the
// panel draws it and the status line stays as it was.
func TestStreamStatusMessageReachesTheStatusLineWhenThePanelHasNoRow(t *testing.T) {
	const message = "Export failed: permission denied"
	for _, tc := range []struct {
		height    int
		inStatus  bool
		inPanel   bool
		helpShown bool
	}{
		{height: 8, inStatus: true}, // 6-row body, help off: no spare row
		{height: 7, inStatus: true}, // below the minimum: the notice owns the body
		{height: 12, inPanel: true}, // spare rows: the panel's footer shows it
		{height: 30, inPanel: true},
	} {
		m := newFitModel(t, fitCase{tab: TabStream, mode: tabVizModeTable}, tc.helpShown, 100, tc.height)
		m.streamModel.SetStatusMessage(message)
		out := plainLines(m.View().Content)
		lastLine := out[len(out)-1]
		if got := strings.Contains(lastLine, message); got != tc.inStatus {
			t.Errorf("height %d: status line carries the message = %v, want %v:\n%s", tc.height, got, tc.inStatus, strings.Join(out, "\n"))
		}
		inBody := strings.Contains(strings.Join(out[:len(out)-1], "\n"), message)
		if tc.inPanel && !inBody {
			t.Errorf("height %d: the panel's footer lost the message:\n%s", tc.height, strings.Join(out, "\n"))
		}
		if tc.inStatus && lipgloss.Height(m.View().Content) > tc.height {
			t.Errorf("height %d: the frame outgrew the terminal", tc.height)
		}
	}
	// No message: no badge on the Stream tab, as before.
	m := newFitModel(t, fitCase{tab: TabStream, mode: tabVizModeTable}, false, 100, 8)
	if len(m.statusTail().badges) != 0 {
		t.Fatalf("badges = %q without a status message", m.statusTail().badges)
	}
}

func plainLines(s string) []string {
	return strings.Split(ansi.Strip(s), "\n")
}
