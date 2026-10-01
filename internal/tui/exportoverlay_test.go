package tui

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"ior/internal/statsengine"
	"ior/internal/tui/eventstream"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// overlayWidths are the terminal widths the export overlay tests sweep: one
// column (no box fits), the narrowest whole box (7), the modal's minimum
// width (30), the whole key hint (52) and a wide terminal with the styled tab
// bar. Kept short: every width costs 15 screens x 30 heights x two renders.
var overlayWidths = []int{1, 7, 30, 52, 120}

// newOverlayTestModel builds a dashboard model with some stream rows and a
// snapshot, on dashboard tab key tab ("1".."7"), with the expanded help bar
// when help is set, and the export modal closed.
func newOverlayTestModel(t *testing.T, tab string, help bool) *Model {
	t.Helper()
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	rb := eventstream.NewRingBuffer()
	for i := range 5 {
		rb.Push(eventstream.StreamEvent{Seq: uint64(i + 1), Syscall: "write", Comm: "proc", PID: 1, FD: 3})
	}
	m.dashboard.SetStreamSource(rb)
	m = updateModel(m, StatsTickMsg{Snap: &statsengine.Snapshot{TotalSyscalls: 99}})
	m = updateModel(m, tea.WindowSizeMsg{Width: 120, Height: 30})
	m = updateModel(m, tea.KeyPressMsg{Code: []rune(tab)[0], Text: tab})
	if help {
		m = updateModel(m, tea.KeyPressMsg{Code: tea.KeyF1})
	}
	return m
}

// updateModel feeds msg to m and returns the updated model.
func updateModel(m *Model, msg tea.Msg) *Model {
	next, _ := m.Update(msg)
	return next.(*Model)
}

// overlayFrames resizes m to width x height and returns its frame with the
// export modal closed (the base) and open.
func overlayFrames(m *Model, width, height int) (base, overlay string) {
	m = updateModel(m, tea.WindowSizeMsg{Width: width, Height: height})
	m.exporter = m.exporter.Close()
	base = m.View().Content
	m.exporter = m.exporter.Open()
	overlay = m.View().Content
	m.exporter = m.exporter.Close()
	return base, overlay
}

// TestExportOverlayFitsTheTerminal holds the frame with the export modal
// open to the terminal on every dashboard tab, with and without the help
// bar, and on the PID picker, at heights 1..30 and the overlayWidths widths
// (1, 7, 30, 52 and 120 columns): it may not be taller or wider than the
// terminal (it used to be the modal's full screen stacked above the whole
// dashboard, about twice the height, task ns2), and where there is room it
// shows the modal whole between the untouched tab bar and status line
// (assertOverlayContent).
func TestExportOverlayFitsTheTerminal(t *testing.T) {
	for _, tab := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		for _, help := range []bool{false, true} {
			t.Run(fmt.Sprintf("tab=%s/help=%v", tab, help), func(t *testing.T) {
				m := newOverlayTestModel(t, tab, help)
				sweepOverlaySizes(t, m)
			})
		}
	}
	t.Run("picker", func(t *testing.T) {
		m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
		if m.router.current() != ScreenPIDPicker {
			t.Fatalf("expected the model to start on the PID picker")
		}
		sweepOverlaySizes(t, m)
	})
}

// sweepOverlaySizes checks m's export overlay frame at every height 1..30
// and every overlayWidths width.
func sweepOverlaySizes(t *testing.T, m *Model) {
	t.Helper()
	for _, width := range overlayWidths {
		for height := 1; height <= 30; height++ {
			base, frame := overlayFrames(m, width, height)
			if got := lipgloss.Height(frame); got > height {
				t.Fatalf("%dx%d: overlay frame is %d rows tall:\n%s", width, height, got, frame)
			}
			for i, line := range strings.Split(frame, "\n") {
				if got := ansi.StringWidth(line); got > width {
					t.Fatalf("%dx%d: overlay line %d is %d cells wide: %q", width, height, i, got, line)
				}
			}
			assertOverlayContent(t, base, frame, width, height)
		}
	}
}

// compactBoxRows is the height of the export modal's most compact box (no
// paused note, no status): border, the two options and the key hint.
const compactBoxRows = 5

// assertOverlayContent checks what an overlay frame shows where the
// terminal has room for it. From compactBoxRows rows and 30 columns the
// modal's options and key hint (whole from 52 columns), from 14 rows (where
// one of the regions beside the base's tab bar and status line has six rows)
// its title too. When the region between the base's first line (the tab
// bar) and its last (the status line), or the blank rows below a short
// base, fits the compact box, both lines stay where the base has them, and
// a base filling the frame keeps its status line last from compactBoxRows+1
// rows. The base is drawn under the modal, not a second time below it.
func assertOverlayContent(t *testing.T, base, frame string, width, height int) {
	t.Helper()
	text := ansi.Strip(frame)
	if height >= compactBoxRows && width >= 30 {
		want := []string{"> CSV stream rows", "Cancel", "Enter confirm"}
		if height >= 14 {
			want = append(want, "Export Stream CSV")
		}
		if width >= 52 {
			want = append(want, "Enter confirm • Esc cancel")
		}
		for _, w := range want {
			if !strings.Contains(text, w) {
				t.Fatalf("%dx%d: overlay lacks %q:\n%s", width, height, w, text)
			}
		}
	}
	baseLines := plainLines(base, width)
	baseRows := drawnRows(baseLines)
	if baseRows == 0 || baseRows > height {
		return
	}
	lines := plainLines(frame, width)
	if max(baseRows-2, height-baseRows) >= compactBoxRows {
		assertLineAt(t, lines, baseLines, 0, "tab bar", width, height)
		assertLineAt(t, lines, baseLines, baseRows-1, "status line", width, height)
	} else if baseRows == height && height > compactBoxRows {
		assertLineAt(t, lines, baseLines, baseRows-1, "status line", width, height)
	}
}

// drawnRows is the number of lines up to the last non-blank one.
func drawnRows(lines []string) int {
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] != "" {
			return i + 1
		}
	}
	return 0
}

// assertLineAt fails unless the frame's line at is the base's line there,
// and the frame has that line no more often than the base: a base drawn a
// second time below the modal would repeat it.
func assertLineAt(t *testing.T, lines, baseLines []string, at int, what string, width, height int) {
	t.Helper()
	want := baseLines[at]
	if want == "" {
		return
	}
	if at >= len(lines) || lines[at] != want || count(lines, want) > count(baseLines, want) {
		t.Fatalf("%dx%d: %s %q must be line %d and not be repeated:\n%s",
			width, height, what, want, at, strings.Join(lines, "\n"))
	}
}

// count is the number of lines equal to want.
func count(lines []string, want string) int {
	n := 0
	for _, line := range lines {
		if line == want {
			n++
		}
	}
	return n
}

// autoResetCountdown matches the status line's auto-reset countdown, which
// may tick between the two renders compared.
var autoResetCountdown = regexp.MustCompile(`auto-reset: \d+s`)

// plainLines is s split into lines with styling and trailing blanks
// stripped and each cut to width cells, the frame as a terminal width
// columns wide shows it (the picker's own lines may be wider; the overlay
// canvas cuts them), with the auto-reset countdown masked.
func plainLines(s string, width int) []string {
	lines := strings.Split(ansi.Strip(s), "\n")
	for i, line := range lines {
		line = strings.TrimRight(ansi.Truncate(line, width, ""), " ")
		lines[i] = autoResetCountdown.ReplaceAllString(line, "auto-reset: Ns")
	}
	return lines
}

// TestPlaceOverlayBox pins where placeOverlayBox puts a box, with a stand-in
// modal whose layouts are 9, 7 and 5 rows tall: between a base's tab bar and
// status line, below a short base, else fitted to the whole frame above its
// last row, else (no room even for 5 rows) at the top.
func TestPlaceOverlayBox(t *testing.T) {
	render := func(_, height int) string {
		rows := 5
		for _, r := range []int{9, 7} {
			if r <= height {
				rows = r
				break
			}
		}
		return strings.Repeat("x\n", rows-1) + "x"
	}
	cases := []struct {
		baseRows, height, rows, top int
	}{
		{30, 30, 9, 10}, // centred between rows 0 and 29
		{9, 30, 9, 15},  // the 21 blank rows below the base are the larger region
		{3, 30, 9, 12},  // below a three-row base
		{14, 20, 9, 2},  // over the body: the 6 rows below are the smaller region
		{7, 7, 5, 1},    // the compact box between tab bar and status line
		{6, 6, 5, 0},    // covers the tab bar, keeps the status line
		{5, 9, 7, 1},    // neither region fits: the frame's height-2 rows
		{3, 3, 5, 0},    // nothing fits: the compact box from the top, clipped
	}
	for _, c := range cases {
		box, top := placeOverlayBox(render, c.baseRows, 40, c.height)
		if rows := lipgloss.Height(box); rows != c.rows || top != c.top {
			t.Fatalf("base %d rows, frame %d: box of %d rows at %d, want %d at %d",
				c.baseRows, c.height, rows, top, c.rows, c.top)
		}
	}
}

// TestFitOverlayBoxReservesTwoRowsFirst pins fitOverlayBox's order with a
// stand-in modal that fills any area of at least 5 rows (so a box of
// height-2 rows tells a first try at height-2 from one at height-1): it
// keeps both the tab bar and the status line where a height-2 box fits,
// then only the status line, then neither.
func TestFitOverlayBoxReservesTwoRowsFirst(t *testing.T) {
	render := func(_, height int) string {
		rows := max(height, 5)
		return strings.Repeat("x\n", rows-1) + "x"
	}
	cases := []struct {
		baseRows, height, rows, top int
	}{
		{5, 9, 7, 1}, // both regions under 5 rows: a height-2 box, rows 1..7
		{5, 8, 6, 1}, // the same one row shorter
		{6, 6, 5, 0}, // height-1: the status line kept
		{5, 5, 5, 0}, // all rows
	}
	for _, c := range cases {
		box, top := placeOverlayBox(render, c.baseRows, 40, c.height)
		if rows := lipgloss.Height(box); rows != c.rows || top != c.top {
			t.Fatalf("base %d rows, frame %d: box of %d rows at %d, want %d at %d",
				c.baseRows, c.height, rows, top, c.rows, c.top)
		}
	}
}
