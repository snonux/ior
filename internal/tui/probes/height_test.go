package probes

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ior/internal/probemanager"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// manyProbes returns n active probe states named sys_000.. so tests can
// overflow any terminal height.
func manyProbes(n int) []probemanager.ProbeState {
	states := make([]probemanager.ProbeState, n)
	for i := range states {
		states[i] = probemanager.ProbeState{Syscall: fmt.Sprintf("sys_%03d", i), Active: true}
	}
	return states
}

// probeModalState puts a freshly opened modal into one of the chrome states
// whose extra lines used to be ignored by the fixed "height-9" row budget.
func probeModalState(t *testing.T, m Model, state string) Model {
	t.Helper()
	switch state {
	case "normal":
	case "search":
		m, _ = m.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
	case "filter":
		m, _ = m.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
		m, _ = m.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
		m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	case "error":
		m, _ = m.Update(ProbeToggledMsg{Err: errors.New("toggle failed: " + strings.Repeat("permission denied ", 8))})
	case "search+error":
		m, _ = m.Update(ProbeToggledMsg{Err: errors.New("toggle failed")})
		m, _ = m.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
	default:
		t.Fatalf("unknown state %q", state)
	}
	return m
}

// TestViewNeverExceedsTerminalHeight is the task jo2 regression test: with
// 300 probes the modal used to render 24/25/27 lines into a 24-line terminal
// (normal/search/error) because the row budget ignored the search line, the
// error block and the wrapped help footer.
func TestViewNeverExceedsTerminalHeight(t *testing.T) {
	states := []string{"normal", "search", "filter", "error", "search+error"}
	widths := []int{30, 48, 60, 70, 80, 200}
	heights := []int{1, 3, 5, 8, 10, 12, 15, 24, 40}
	for _, state := range states {
		for _, w := range widths {
			for _, h := range heights {
				m := NewModel(&fakeManager{states: manyProbes(300)}).SetSize(w, h).Open()
				m = probeModalState(t, m, state)
				view := m.View(w, h)
				if got := lipgloss.Height(view); got > h {
					t.Errorf("state=%s %dx%d: rendered %d lines, want <= %d", state, w, h, got, h)
				}
			}
		}
	}
}

// TestViewFillsTerminalHeightExactly guards against over-correcting: on a
// terminal big enough for the chrome, the scrolled list must use every line
// (the modal is as tall as the terminal), not leave rows unused.
func TestViewFillsTerminalHeightExactly(t *testing.T) {
	for _, state := range []string{"normal", "search", "error"} {
		for _, w := range []int{50, 80} {
			m := NewModel(&fakeManager{states: manyProbes(300)}).SetSize(w, 24).Open()
			m = probeModalState(t, m, state)
			l := m.layout()
			box := l.box.Render(strings.Join(m.buildProbeLines(l, m.filtered()), "\n"))
			if got := lipgloss.Height(box); got != 24 {
				t.Errorf("state=%s width=%d: box height %d, want 24", state, w, got)
			}
		}
	}
}

// TestSelectionVisibleInEveryState scrolls to the bottom and checks the
// selected probe is still drawn after the chrome grows (search, error) and
// on a terminal narrower than the modal, where the help wraps further.
func TestSelectionVisibleInEveryState(t *testing.T) {
	for _, state := range []string{"normal", "search", "error", "search+error"} {
		for _, w := range []int{48, 80} {
			m := NewModel(&fakeManager{states: manyProbes(40)}).SetSize(w, 20).Open()
			for i := 0; i < 39; i++ {
				m, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
			}
			m = probeModalState(t, m, state)
			if view := m.View(w, 20); !strings.Contains(view, "> [x] sys_039") {
				t.Errorf("state=%s width=%d: selected probe sys_039 not rendered:\n%s", state, w, view)
			}
		}
	}
}

// TestProbeRowsWithErrorsStayOneLine checks a probe row carrying an error
// annotation is cut to the content width instead of wrapping, since
// visibleRows budgets exactly one line per row.
func TestProbeRowsWithErrorsStayOneLine(t *testing.T) {
	probes := manyProbes(50)
	for i := range probes {
		probes[i].Syscall = strings.Repeat("x", 24)
		probes[i].Error = strings.Repeat("attach failed ", 5)
	}
	m := NewModel(&fakeManager{states: probes}).SetSize(80, 24).Open()
	if got := lipgloss.Height(m.View(80, 24)); got > 24 {
		t.Fatalf("rendered %d lines, want <= 24", got)
	}
	l := m.layout()
	for _, line := range m.buildProbeLines(l, m.filtered()) {
		if !strings.Contains(line, "attach failed") {
			continue // header/footer may wrap; only rows are budgeted one line
		}
		if w := lipgloss.Width(line); w > contentWidth(l.box) {
			t.Fatalf("line %q is %d cells, wider than content width %d", line, w, contentWidth(l.box))
		}
	}
}

// TestSearchModeClampsStoredOffset checks Update (not only View) keeps the
// stored scroll offset consistent when entering search shrinks the row budget.
func TestSearchModeClampsStoredOffset(t *testing.T) {
	m := NewModel(&fakeManager{states: manyProbes(60)}).SetSize(80, 24).Open()
	before := m.visibleRows()
	for i := 0; i < before-1; i++ {
		m, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	m, _ = m.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
	rows := m.visibleRows()
	if rows >= before {
		t.Fatalf("search rows = %d, want fewer than normal rows %d", rows, before)
	}
	if m.cursor < m.offset || m.cursor >= m.offset+rows {
		t.Fatalf("cursor %d outside stored window [%d,%d)", m.cursor, m.offset, m.offset+rows)
	}
}

// assertCursorInWindow fails when the stored cursor lies outside the stored
// scroll window, i.e. when View would not draw the selected row.
func assertCursorInWindow(t *testing.T, m Model, context string) {
	t.Helper()
	rows := m.visibleRows()
	if m.cursor < m.offset || m.cursor >= m.offset+rows {
		t.Fatalf("%s: cursor %d outside stored window [%d,%d)", context, m.cursor, m.offset, m.offset+rows)
	}
}

// selectedLine returns the rendered row carrying the "> " selection marker.
func selectedLine(view string) string {
	for _, line := range strings.Split(view, "\n") {
		if i := strings.Index(line, "> ["); i >= 0 {
			return strings.TrimSpace(line[i:])
		}
	}
	return ""
}

// TestNarrowTerminalScrollMovesSelectionEveryPress is the jo2 review
// regression: below 70 columns the error and help wrap to more lines than at
// the 80-column width Update used to assume, so the stored offset disagreed
// with the rows View drew and scrolling up looked stuck, then jumped. With
// SetSize the budget matches and every key press moves the drawn selection.
func TestNarrowTerminalScrollMovesSelectionEveryPress(t *testing.T) {
	const w, h = 48, 30
	m := NewModel(&fakeManager{states: manyProbes(300)}).SetSize(w, h).Open()
	m = probeModalState(t, m, "error")
	for i := 0; i < 299; i++ {
		m, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	prev := selectedLine(m.View(w, h))
	for i := 0; i < 60; i++ {
		m, _ = m.Update(tea.KeyPressMsg{Code: 'k', Text: "k"})
		assertCursorInWindow(t, m, fmt.Sprintf("press %d", i))
		cur := selectedLine(m.View(w, h))
		want := fmt.Sprintf("sys_%03d", m.cursor)
		if cur == prev || !strings.Contains(cur, want) {
			t.Fatalf("press %d: selection %q (previous %q), want row %s", i, cur, prev, want)
		}
		prev = cur
	}
}

// TestLeavingSearchReclampsStoredOffset checks esc out of search re-clamps:
// the chrome changes, and the stored window must still hold the cursor.
func TestLeavingSearchReclampsStoredOffset(t *testing.T) {
	for _, w := range []int{30, 48, 80} {
		m := NewModel(&fakeManager{states: manyProbes(60)}).SetSize(w, 20).Open()
		m = probeModalState(t, m, "search+error")
		for i := 0; i < 5; i++ {
			m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
		}
		m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
		if m.searching {
			t.Fatalf("width %d: esc did not leave search", w)
		}
		assertCursorInWindow(t, m, fmt.Sprintf("width %d after esc", w))
		for i := 0; i < 59; i++ {
			m, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
			assertCursorInWindow(t, m, fmt.Sprintf("width %d press %d", w, i))
		}
	}
}

// TestViewNeverExceedsTerminalWidth covers follow-up 8p2: the modal used to
// be at least 44 columns wide, overflowing terminals narrower than 48.
func TestViewNeverExceedsTerminalWidth(t *testing.T) {
	for _, state := range []string{"normal", "search", "error"} {
		for _, w := range []int{1, 5, 10, 20, 30, 40, 47, 48, 60, 70, 200} {
			m := NewModel(&fakeManager{states: manyProbes(30)}).SetSize(w, 24).Open()
			m = probeModalState(t, m, state)
			view := m.View(w, 24)
			if got := lipgloss.Width(view); got > w {
				t.Errorf("state=%s width=%d: rendered %d columns", state, w, got)
			}
			if got := lipgloss.Height(view); got > 24 {
				t.Errorf("state=%s width=%d: rendered %d lines", state, w, got)
			}
		}
	}
}

// TestProbeModalWidth pins the width policy: preferred 66 with margins,
// shrinking to minModalWidth, then the whole terminal, never wider than it.
func TestProbeModalWidth(t *testing.T) {
	cases := map[int]int{200: 66, 70: 66, 69: 65, 30: 26, 28: 24, 26: 24, 24: 24, 20: 20, 1: 1, 0: 0}
	for term, want := range cases {
		if got := probeModalWidth(term); got != want {
			t.Errorf("probeModalWidth(%d) = %d, want %d", term, got, want)
		}
	}
}

// TestGrowingHeightPullsOffsetBack is the jo2 review 2 regression: with the
// list scrolled to its end, a taller terminal must show more probes rather
// than keep the old offset and pad the window with blank rows.
func TestGrowingHeightPullsOffsetBack(t *testing.T) {
	const total = 300
	m := NewModel(&fakeManager{states: manyProbes(total)}).SetSize(80, 24).Open()
	for i := 0; i < total-1; i++ {
		m, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	m = m.SetSize(80, 50)
	rows := m.visibleRows()
	if m.offset != total-rows {
		t.Fatalf("offset = %d, want %d (len - rows)", m.offset, total-rows)
	}
	l := m.layout()
	box := l.box.Render(strings.Join(m.buildProbeLines(l, m.filtered()), "\n"))
	if got := lipgloss.Height(box); got != 50 {
		t.Fatalf("box height = %d, want 50 (window filled)", got)
	}
	assertCursorInWindow(t, m, "after growing")
}

// TestLeavingSearchAtEndPullsOffsetBack checks the same pull-back when the
// budget grows because the search line disappears (esc out of search).
func TestLeavingSearchAtEndPullsOffsetBack(t *testing.T) {
	const total = 100
	m := NewModel(&fakeManager{states: manyProbes(total)}).SetSize(80, 24).Open()
	for i := 0; i < total-1; i++ {
		m, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	// Entering search shrinks the budget, scrolling the end one row further.
	m, _ = m.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
	if want := total - m.visibleRows(); m.offset != want {
		t.Fatalf("offset = %d, want %d while searching", m.offset, want)
	}
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if want := total - m.visibleRows(); m.offset != want {
		t.Fatalf("offset = %d, want %d after leaving search", m.offset, want)
	}
}
