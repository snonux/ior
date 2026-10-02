package tui

import (
	"strings"
	"testing"

	"ior/internal/tui/eventstream"

	tea "charm.land/bubbletea/v2"
)

// warningViewHint is the key hint only the Stream tab's warning modal draws.
const warningViewHint = "Esc/Enter close"

// warningViewMessage ends in advice a 120-column warning row cuts off.
const warningViewMessage = "ior: -tid 2: not a thread of -pid 1: the trace will stay empty. " +
	"Pick a thread of that process, or drop -tid, and start the trace again to see its syscalls here."

// openWarningView drives a real model to the Stream tab's warning modal
// (task b23): 7 selects the tab, space pauses, G selects the newest row, the
// warning, and Enter opens the modal with its whole message.
func openWarningView(t *testing.T) *Model {
	t.Helper()
	m := newTypingTestModel()
	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "write", Comm: "proc", PID: 42, TID: 42, FD: 7})
	rb.Push(eventstream.NewWarningEvent(2, warningViewMessage))
	m.dashboard.SetStreamSource(rb)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)
	for _, key := range []tea.KeyPressMsg{text("7"), text(" "), text("G")} {
		m = press(t, m, key)
	}
	requireViewContains(t, m, "Enter show warning")
	if strings.Contains(m.View().Content, "syscalls here.") {
		t.Fatalf("the warning row already shows the whole message:\n%s", m.View().Content)
	}
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	requireViewContains(t, m, warningViewHint)
	requireViewContains(t, m, "syscalls here.")
	return m
}

// TestQClosesTheStreamWarningViewInsteadOfQuitting: q inside the modal
// closes it, like every other overlay, and only a second q quits.
func TestQClosesTheStreamWarningViewInsteadOfQuitting(t *testing.T) {
	m := openWarningView(t)
	m = press(t, m, text("q"))
	if m.quitting {
		t.Fatalf("q inside the warning view quit ior")
	}
	if strings.Contains(m.View().Content, warningViewHint) {
		t.Fatalf("expected q to close the warning view, view:\n%s", m.View().Content)
	}
	requireViewContains(t, m, "PAUSED")
	m = press(t, m, text("q"))
	if !m.quitting {
		t.Fatalf("expected q on the stream tab to quit once the view is closed")
	}
}

// TestStreamWarningViewBlocksGlobalShortcuts: Esc, Enter and ctrl+c (which
// the quit binding also matches) close the modal too, and the dashboard's
// own shortcuts stay inert behind it.
func TestStreamWarningViewBlocksGlobalShortcuts(t *testing.T) {
	for _, k := range []tea.KeyPressMsg{{Code: tea.KeyEsc}, {Code: tea.KeyEnter}, {Code: 'c', Mod: tea.ModCtrl}} {
		m := openWarningView(t)
		m = press(t, m, k)
		if m.quitting || strings.Contains(m.View().Content, warningViewHint) {
			t.Fatalf("%v: quitting=%v, expected only the warning view to close", k, m.quitting)
		}
		requireViewContains(t, m, "PAUSED")
	}
	for _, s := range []string{"1", "f", "R", "o", "r", "v", " ", "/"} {
		m := openWarningView(t)
		m = press(t, m, text(s))
		if m.quitting || m.filterModal.Visible() || m.recordModal.Visible() || m.probeModal.Visible() {
			t.Fatalf("key %q acted on the dashboard behind the warning view", s)
		}
		requireViewContains(t, m, warningViewHint)
	}
}
