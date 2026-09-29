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
				m := NewModel(&fakeManager{states: manyProbes(300)}).SetHeight(h).Open()
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
			m := NewModel(&fakeManager{states: manyProbes(300)}).SetHeight(24).Open()
			m = probeModalState(t, m, state)
			m.width = w
			box := m.boxStyle().Render(strings.Join(m.buildProbeLines(), "\n"))
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
			m := NewModel(&fakeManager{states: manyProbes(40)}).SetHeight(20).Open()
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
	m := NewModel(&fakeManager{states: probes}).SetHeight(24).Open()
	if got := lipgloss.Height(m.View(80, 24)); got > 24 {
		t.Fatalf("rendered %d lines, want <= 24", got)
	}
	for _, line := range m.buildProbeLines() {
		if !strings.Contains(line, "attach failed") {
			continue // header/footer may wrap; only rows are budgeted one line
		}
		if w := lipgloss.Width(line); w > m.contentWidth() {
			t.Fatalf("line %q is %d cells, wider than content width %d", line, w, m.contentWidth())
		}
	}
}

// TestSearchModeClampsStoredOffset checks Update (not only View) keeps the
// stored scroll offset consistent when entering search shrinks the row budget.
func TestSearchModeClampsStoredOffset(t *testing.T) {
	m := NewModel(&fakeManager{states: manyProbes(60)}).SetHeight(24).Open()
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
