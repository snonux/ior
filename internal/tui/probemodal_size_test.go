package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/tui/probes"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// TestProbeModalHonoursNarrowWindowSize pins the SetSize plumbing from the
// TUI into the probes modal (window resize, the probes key, picker reset):
// on a narrow 48x20 terminal the error and help wrap to more lines than at
// 80 columns, so a modal that only learnt the height would budget too many
// rows — overflowing the screen and scrolling the selection out of view.
func TestProbeModalHonoursNarrowWindowSize(t *testing.T) {
	const w, h, total = 48, 20, 120
	states := make([]probemanager.ProbeState, total)
	for i := range states {
		states[i] = probemanager.ProbeState{Syscall: fmt.Sprintf("sys_%03d", i), Active: true}
	}
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.runtime.setProbeManager(fakeProbeManager{states: states})
	m.router.showDashboard()
	m.attaching = false

	next, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: '2', Text: "2"}) // leave flame tab: 'o' orders flames there
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: 'o', Text: "o"})
	m = next.(*Model)
	if !m.probeModal.Visible() {
		t.Fatalf("expected the probes key to open the probes modal")
	}
	next, _ = m.Update(probes.ProbeToggledMsg{Err: errors.New("toggle failed: " + strings.Repeat("permission denied ", 6))})
	m = next.(*Model)

	cursor := 0
	press := func(key rune, delta int, n int) {
		for i := 0; i < n; i++ {
			next, _ = m.Update(tea.KeyPressMsg{Code: key, Text: string(key)})
			m = next.(*Model)
			cursor += delta
			assertProbeFrame(t, m.View().Content, h, cursor)
		}
	}
	press('j', 1, total-1)
	press('k', -1, 30)
}

// assertProbeFrame fails when the rendered TUI frame is taller than the
// terminal or does not draw the probe row selected by cursor.
func assertProbeFrame(t *testing.T, out string, height, cursor int) {
	t.Helper()
	if got := lipgloss.Height(out); got > height {
		t.Fatalf("cursor %d: frame is %d lines, want <= %d", cursor, got, height)
	}
	if want := fmt.Sprintf("> [x] sys_%03d", cursor); !strings.Contains(out, want) {
		t.Fatalf("cursor %d: selected row %q not rendered:\n%s", cursor, want, out)
	}
}
