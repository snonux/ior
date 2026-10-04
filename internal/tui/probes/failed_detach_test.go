package probes

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// The modal over a real probe manager whose links report an error when they
// are destroyed. A link's Destroy is final (probemanager.Link), so the probe
// is off afterwards: the modal shows it unchecked with the error, the toggle
// attaches it again like any detached probe, and a family detach counts it
// among the detached.

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

// batchResult follows the family batch started by cmd to its end and returns
// its result.
func batchResult(t *testing.T, cmd tea.Cmd) FamilyToggledMsg {
	t.Helper()
	for range 100 {
		switch msg := cmd().(type) {
		case FamilyBatchProgressMsg:
			cmd = msg.Next()
		case FamilyToggledMsg:
			return msg
		default:
			t.Fatalf("unexpected batch message %T", msg)
		}
	}
	t.Fatal("batch did not finish")
	return FamilyToggledMsg{}
}

// TestFamilyDetachWhoseDestroysReportedAnErrorSaysAllAreDetached: a family
// detach over links that report an error detaches every probe all the same,
// and the outcome must say so. It used to read "detached 0 of 2 probes" and
// "2 failed" beside a Families row that showed none of them attached.
func TestFamilyDetachWhoseDestroysReportedAnErrorSaysAllAreDetached(t *testing.T) {
	mgr := probemanager.NewManager(&busyAttacher{t: t})
	tracepoints := []string{"sys_enter_read", "sys_exit_read", "sys_enter_write", "sys_exit_write"}
	if err := mgr.AttachAll(nil, tracepoints, nil); err != nil {
		t.Fatalf("AttachAll: %v", err)
	}
	done := batchResult(t, StartFamilyBatch(context.Background(), mgr, 1, types.FamilyFS, false))
	m := NewModel(mgr).Open().FinishBatch(done, "")

	if m.lastInfo != "FS: detached 2 of 2 probes" {
		t.Fatalf("lastInfo = %q, want both probes detached", m.lastInfo)
	}
	if want := "2 reported an error, first read: detach enter read: link busy"; !strings.HasPrefix(m.lastErr, want) {
		t.Fatalf("lastErr = %q, want it to begin %q", m.lastErr, want)
	}
	if active, total := mgr.ActiveCount(); active != 0 || total != 2 {
		t.Fatalf("ActiveCount = %d/%d after the detach, want 0/2", active, total)
	}
}

// TestFamilyOutcomeCountsADetachWithAnErrorAsDetached pins the two wordings
// side by side for the same result: of three probes one reported an error. A
// detach has detached all three; an attach has attached two, and one failed.
func TestFamilyOutcomeCountsADetachWithAnErrorAsDetached(t *testing.T) {
	result := probemanager.BatchResult{Total: 3, Changed: 2, Errors: []probemanager.SyscallError{
		{Syscall: "read", Err: errors.New("link busy")},
	}}
	for _, tc := range []struct {
		attach        bool
		info, errText string
	}{
		{false, "FS: detached 3 of 3 probes", "1 reported an error, first read: link busy"},
		{true, "FS: attached 2 of 3 probes", "1 failed, first read: link busy"},
	} {
		info, errText := familyOutcome(FamilyToggledMsg{Family: types.FamilyFS, Attach: tc.attach, Result: result})
		if info != tc.info || errText != tc.errText {
			t.Errorf("attach %t: outcome = %q / %q, want %q / %q", tc.attach, info, errText, tc.info, tc.errText)
		}
	}
	clean := probemanager.BatchResult{Total: 3, Changed: 3}
	info, errText := familyOutcome(FamilyToggledMsg{Family: types.FamilyFS, Result: clean})
	if info != "FS: detached 3 of 3 probes" || errText != "" {
		t.Errorf("clean detach: outcome = %q / %q, want all three detached and no error", info, errText)
	}
}
