package probes

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"ior/internal/probemanager"

	tea "charm.land/bubbletea/v2"
)

// The modal over a real probe manager whose links report an error when they
// are destroyed. A link's Destroy is final (probemanager.Link), so the probe
// is off afterwards: the modal shows it unchecked with the error, and the
// toggle attaches it again like any detached probe.

// busyLink is a link whose Destroy reports an error, and that fails the test
// when it is destroyed a second time: the real link is freed by the first.
type busyLink struct {
	t        *testing.T
	destroys atomic.Int32
}

func (l *busyLink) Destroy() error {
	if n := l.destroys.Add(1); n > 1 {
		l.t.Errorf("Destroy call %d on a link that was gone after the first", n)
	}
	return errors.New("link busy")
}

// busyAttacher hands out a fresh busyLink at every attach and counts them.
type busyAttacher struct {
	t     *testing.T
	links atomic.Int32
}

func (a *busyAttacher) GetProgram(string) (probemanager.Program, error) { return a, nil }

func (a *busyAttacher) AttachTracepoint(string, string) (probemanager.Link, error) {
	a.links.Add(1)
	return &busyLink{t: a.t}, nil
}

// pressSpace toggles the selected probe and feeds the result back, as the
// TUI does.
func pressSpace(t *testing.T, m Model) Model {
	t.Helper()
	m, cmd := m.Update(tea.KeyPressMsg{Code: ' ', Text: " "})
	if cmd == nil {
		t.Fatal("space on a probe row returned no toggle command")
	}
	m, _ = m.Update(cmd())
	return m
}

// TestProbeWhoseDetachReportedAnErrorIsShownOffAndTogglesOn: the detach
// destroyed both links although each reported an error, so the row is
// unchecked with the error beside it and the count is 0/1. The next toggle is
// an attach - two fresh links - and clears the error.
func TestProbeWhoseDetachReportedAnErrorIsShownOffAndTogglesOn(t *testing.T) {
	attacher := &busyAttacher{t: t}
	mgr := probemanager.NewManager(attacher)
	if err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read"}, nil); err != nil {
		t.Fatalf("AttachAll: %v", err)
	}
	m := NewModel(mgr).Open()

	m = pressSpace(t, m)
	view := m.View(100, 40)
	if !strings.Contains(view, "[ ] read") || !strings.Contains(view, " ! detach enter read") {
		t.Fatalf("view after the failed detach, want read unchecked with its error:\n%s", view)
	}
	if !strings.Contains(view, "Error: detach enter read: link busy; detach exit read") {
		t.Fatalf("view after the failed detach, want the error line:\n%s", view)
	}
	if active, total := mgr.ActiveCount(); active != 0 || total != 1 {
		t.Fatalf("ActiveCount = %d/%d after the detach, want 0/1", active, total)
	}

	m = pressSpace(t, m)
	view = m.View(100, 40)
	if !strings.Contains(view, "[x] read") || strings.Contains(view, "link busy") {
		t.Fatalf("view after the second toggle, want read checked without an error:\n%s", view)
	}
	if got := attacher.links.Load(); got != 4 {
		t.Fatalf("%d links attached in all, want 4: both tracepoints at startup and again", got)
	}
}
