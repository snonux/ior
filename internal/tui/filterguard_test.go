package tui

import (
	"context"
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/tui/messages"
	"ior/internal/types"
)

// liveFilterRecorder stands in for the running eventloop's SetFilter: the TUI
// registers it as the live-filter setter, so every filter it records is one
// that reached the running trace pipeline in-place, with no restart.
type liveFilterRecorder struct {
	applied []globalfilter.Filter
}

func (r *liveFilterRecorder) set(filter globalfilter.Filter) {
	r.applied = append(r.applied, filter)
}

// newLiveSwapModel builds a dashboard-screen Model with a registered live
// filter setter, i.e. one on the in-place swap path rather than the restart
// path: reapplyActiveFilter hands the new filter to the setter and never
// stops the trace.
func newLiveSwapModel(t *testing.T) (*Model, *liveFilterRecorder) {
	t.Helper()
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 40
	recorder := &liveFilterRecorder{}
	m.runtime.SetLiveFilterSetter(recorder.set)
	return m, recorder
}

func overLongComm() string {
	return strings.Repeat("a", types.MAX_PROGNAME_LENGTH+4)
}

// TestLiveFilterSwapRefusesAnOverLongCommPattern is the l3 regression: the
// filter modal's apply takes the live-swap path, which restarts nothing, so
// before the guard nothing on it ran ValidateTracepointFields. The pattern is
// longer than the kernel's fixed-size comm field, so matchString could never
// match it and the dashboard simply went empty - live-looking, permanently
// unmatched, with no error anywhere.
func TestLiveFilterSwapRefusesAnOverLongCommPattern(t *testing.T) {
	m, recorder := newLiveSwapModel(t)

	pattern := overLongComm()
	next, _ := m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: pattern}},
	})
	m = next.(*Model)

	if len(recorder.applied) != 0 {
		t.Fatalf("expected the live swap to be refused, but the running pipeline got %d filter(s): %+v",
			len(recorder.applied), recorder.applied)
	}
	if got := m.filters.current(); got.Comm != nil {
		t.Fatalf("expected the previous filter to stay active, got comm %q", got.Comm.Pattern)
	}
	view := m.View().Content
	if !strings.Contains(view, "FILTER REFUSED") {
		t.Fatalf("expected the dashboard to tell the user the filter was refused, got:\n%s", view)
	}
	if !strings.Contains(view, "comm filter max size is 15") {
		t.Fatalf("expected the refusal to state the limit it broke, got:\n%s", view)
	}
}

// TestLiveFilterSwapRefusesAnOverLongPathPattern covers the other fixed-size
// kernel field the same way.
func TestLiveFilterSwapRefusesAnOverLongPathPattern(t *testing.T) {
	m, recorder := newLiveSwapModel(t)

	pattern := strings.Repeat("p", types.MAX_FILENAME_LENGTH+1)
	next, _ := m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: pattern}},
	})
	m = next.(*Model)

	if len(recorder.applied) != 0 {
		t.Fatalf("expected the live swap to be refused, but the running pipeline got %d filter(s)", len(recorder.applied))
	}
	if got := m.filters.current(); got.File != nil {
		t.Fatalf("expected the previous filter to stay active, got path %q", got.File.Pattern)
	}
	if view := m.View().Content; !strings.Contains(view, "FILTER REFUSED") {
		t.Fatalf("expected the dashboard to tell the user the filter was refused, got:\n%s", view)
	}
}

// TestRefusedLiveFilterKeepsTheFilterStackUntouched pins that a refusal is not
// half-applied: no undo level is recorded for a filter that never took effect,
// so the next undo still reverts the last filter the user actually got.
func TestRefusedLiveFilterKeepsTheFilterStackUntouched(t *testing.T) {
	m, recorder := newLiveSwapModel(t)

	next, _ := m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "bash"}},
	})
	m = next.(*Model)
	depth := len(m.filters.stack)
	if depth != 1 {
		t.Fatalf("expected the accepted filter to record one undo level, got %d", depth)
	}

	next, _ = m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: overLongComm()}},
	})
	m = next.(*Model)

	if got := len(m.filters.stack); got != depth {
		t.Fatalf("expected the refused filter to leave the stack at %d, got %d", depth, got)
	}
	if len(recorder.applied) != 1 {
		t.Fatalf("expected only the accepted filter to reach the pipeline, got %d", len(recorder.applied))
	}
	if got := m.filters.current(); got.Comm == nil || got.Comm.Pattern != "bash" {
		t.Fatalf("expected the accepted filter to stay active, got %+v", got.Comm)
	}
}

// TestAcceptedLiveFilterSwapClearsTheRefusalNotice pins the other half of the
// contract: the notice describes the filter change that was refused, so it
// must not survive the next change the user does get.
func TestAcceptedLiveFilterSwapClearsTheRefusalNotice(t *testing.T) {
	m, recorder := newLiveSwapModel(t)

	next, _ := m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: overLongComm()}},
	})
	m = next.(*Model)
	if !strings.Contains(m.View().Content, "FILTER REFUSED") {
		t.Fatalf("expected a refusal notice before the accepted swap")
	}

	next, _ = m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "firefox"}},
	})
	m = next.(*Model)

	if len(recorder.applied) != 1 {
		t.Fatalf("expected the valid filter to reach the running pipeline once, got %d", len(recorder.applied))
	}
	if got := recorder.applied[0]; got.Comm == nil || got.Comm.Pattern != "firefox" {
		t.Fatalf("expected the pipeline to receive the firefox filter, got %+v", got.Comm)
	}
	view := m.View().Content
	if strings.Contains(view, "FILTER REFUSED") {
		t.Fatalf("expected the refusal notice to be gone once a filter was accepted, got:\n%s", view)
	}
}

// TestFamilyCycleRefusesAnUnusableFilter covers the second entry point into the
// same pipeline tail (replaceGlobalFilter): the [ ] family cycle clones the
// active filter, so an unusable one must not be re-applied there either.
func TestFamilyCycleRefusesAnUnusableFilter(t *testing.T) {
	m, recorder := newLiveSwapModel(t)
	// Seed the active filter directly, bypassing the guard, to model a filter
	// that arrived from somewhere other than applyGlobalFilter (the CLI, say).
	m.setGlobalFilter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: overLongComm()}})

	next, _ := m.cycleFamilyScope(+1)
	m = next.(*Model)

	if len(recorder.applied) != 0 {
		t.Fatalf("expected the family re-scope to be refused, got %d filter(s)", len(recorder.applied))
	}
	if view := m.View().Content; !strings.Contains(view, "FILTER REFUSED") {
		t.Fatalf("expected the dashboard to report the refusal, got:\n%s", view)
	}
}

// showsRefusal reports whether the rendered view carries the refusal notice,
// so a test asserts on what the user sees rather than on model state.
func showsRefusal(t *testing.T, m *Model) bool {
	t.Helper()
	return strings.Contains(m.View().Content, "FILTER REFUSED")
}

// TestUndoClearsTheRefusalNotice pins one of the two clears that do not go
// through refuseUnusableFilter. Undo changes the filter on screen, so a notice
// explaining why some *other* filter was refused no longer describes anything
// the user is looking at.
func TestUndoClearsTheRefusalNotice(t *testing.T) {
	m, _ := newLiveSwapModel(t)

	// A filter that is accepted, so undo has somewhere to go back to.
	next, _ := m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "firefox"}},
	})
	m = next.(*Model)

	next, _ = m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: overLongComm()}},
	})
	m = next.(*Model)
	if !showsRefusal(t, m) {
		t.Fatal("the over-long filter was not refused; this test would prove nothing")
	}

	next, _ = m.Update(messages.GlobalFilterUndoRequestedMsg{})
	m = next.(*Model)
	if showsRefusal(t, m) {
		t.Error("the refusal notice survived an undo; it now explains a filter the user is not looking at")
	}
}

// TestPidSelectionClearsTheRefusalNotice pins the other one. Choosing a PID
// rebinds the filter's process dimensions and restarts the trace, so a notice
// from the previous session describes neither the filter on screen nor the
// session it is running in.
func TestPidSelectionClearsTheRefusalNotice(t *testing.T) {
	m, _ := newLiveSwapModel(t)

	next, _ := m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: overLongComm()}},
	})
	m = next.(*Model)
	if !showsRefusal(t, m) {
		t.Fatal("the over-long filter was not refused; this test would prove nothing")
	}

	// Driven through the real message rather than setProcessFilters directly,
	// so this also pins that the PID picker still routes through the clear.
	next, _ = m.Update(messages.PidSelectedMsg{Pid: 4242})
	m = next.(*Model)
	if showsRefusal(t, m) {
		t.Error("the refusal notice survived a PID change and trace restart")
	}
}

// TestLiveFilterSwapAcceptsAnAnchoredLongestComm pins the m3 regression on the
// surface that exposed it. The guard added for l3 turned a latent length-check
// bug into a refusal of `^exact$` - the syntax the filter modal advertises -
// for any comm at the longest length the kernel can deliver. The globalfilter
// test covers the validator; this covers the path a user actually takes.
func TestLiveFilterSwapAcceptsAnAnchoredLongestComm(t *testing.T) {
	m, recorder := newLiveSwapModel(t)

	pattern := "^" + strings.Repeat("a", types.MAX_PROGNAME_LENGTH-1) + "$"
	next, _ := m.Update(messages.GlobalFilterRequestedMsg{
		Filter: globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: pattern}},
	})
	m = next.(*Model)

	if showsRefusal(t, m) {
		t.Fatalf("anchored exact match %q was refused; it is the documented way to match the longest comm", pattern)
	}
	if len(recorder.applied) != 1 {
		t.Errorf("live setter received %d filters, want 1: the swap did not reach the pipeline", len(recorder.applied))
	}
}
