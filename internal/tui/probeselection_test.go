package tui

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	tea "charm.land/bubbletea/v2"

	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/tui/messages"
	"ior/internal/tui/probes"
	"ior/internal/types"
)

// selectionProbeManager is a probe manager whose state the test sets
// directly and whose family batches really flip it. mu guards states:
// family batches run on their own goroutine.
type selectionProbeManager struct {
	fakeProbeManager
	mu sync.Mutex
	// hold, when set, stops a family batch after its first probe until it
	// is closed (or the batch is cancelled), so a test can act while the
	// batch is half done.
	hold chan struct{}
	// inFlight is the number of family batches currently running.
	inFlight atomic.Int32
}

func (f *selectionProbeManager) States() []probemanager.ProbeState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.states)
}

// setActive sets the Active flag of syscall.
func (f *selectionProbeManager) setActive(syscall string, active bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.states {
		if f.states[i].Syscall == syscall {
			f.states[i].Active = active
		}
	}
}

func (f *selectionProbeManager) Attach(syscall string) error {
	f.setActive(syscall, true)
	return nil
}

func (f *selectionProbeManager) Detach(syscall string) error {
	f.setActive(syscall, false)
	return nil
}

func (f *selectionProbeManager) AttachFamily(ctx context.Context, family types.SyscallFamily, progress func(int, int)) (probemanager.BatchResult, error) {
	return f.setFamily(ctx, family, true, progress)
}

func (f *selectionProbeManager) DetachFamily(ctx context.Context, family types.SyscallFamily, progress func(int, int)) (probemanager.BatchResult, error) {
	return f.setFamily(ctx, family, false, progress)
}

// setFamily flips the family's probes one by one. Like the real manager's
// batch it checks ctx before each probe and returns the partial result with
// ctx.Err() once cancelled; the hold after the first probe also ends on
// cancellation. inFlight counts running batches, so a test can tell that a
// cancelled batch's goroutine has returned.
func (f *selectionProbeManager) setFamily(ctx context.Context, family types.SyscallFamily, active bool, progress func(int, int)) (probemanager.BatchResult, error) {
	f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	var result probemanager.BatchResult
	for i := range f.states {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		f.mu.Lock()
		change := f.states[i].Active != active && probemanager.SyscallFamily(f.states[i].Syscall) == family
		if change {
			f.states[i].Active = active
			result.Total++
			result.Changed++
		}
		f.mu.Unlock()
		if change && result.Changed == 1 && f.hold != nil {
			select {
			case <-f.hold:
			case <-ctx.Done():
			}
		}
	}
	progress(result.Total, result.Total)
	return result, nil
}

// newSelectionManager returns read (FS) active and socket/connect (Network)
// and nanosleep (Time) inactive.
func newSelectionManager() *selectionProbeManager {
	return &selectionProbeManager{fakeProbeManager: fakeProbeManager{states: []probemanager.ProbeState{
		{Syscall: "connect"}, {Syscall: "nanosleep"}, {Syscall: "read", Active: true}, {Syscall: "socket"},
	}}}
}

// cycleTo re-scopes m with ']' until the filter is scoped to family.
func cycleTo(t *testing.T, m *Model, family string) *Model {
	t.Helper()
	for range len(types.AllSyscallFamilies()) + 1 {
		next, _ := m.cycleFamilyScope(+1)
		m = next.(*Model)
		if scopedFamily(m.filters.current()) == family {
			return m
		}
	}
	t.Fatalf("family %s never reached", family)
	return m
}

func TestFamilyCycleHintsAtFamilyWithoutAttachedProbes(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	manager := newSelectionManager()
	m.runtime.setProbeManager(manager)

	m = cycleTo(t, m, "Network")
	if view := m.View().Content; !strings.Contains(view, "Network not traced: press o, tab, space to attach") {
		t.Fatalf("expected the not-traced hint for Network, got:\n%s", view)
	}

	// Attaching a probe of the family clears the hint.
	manager.setActive("socket", true)
	next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "socket"})
	m = next.(*Model)
	if view := m.View().Content; strings.Contains(view, "not traced") {
		t.Fatalf("expected the hint to go once Network is attached, got:\n%s", view)
	}

	// FS has an attached probe: no hint there either.
	m = cycleTo(t, m, "FS")
	if view := m.View().Content; strings.Contains(view, "not traced") {
		t.Fatalf("expected no hint for the traced FS family, got:\n%s", view)
	}
}

func TestFamilyHintNeedsAPublishedManager(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	m = cycleTo(t, m, "Network")
	if view := m.View().Content; strings.Contains(view, "not traced") {
		t.Fatalf("attach state is unknown without a manager, yet a hint showed:\n%s", view)
	}
}

// TestFamilyHintNeverClearsARefusal: refreshing the hint on an unscoped
// dashboard must only clear its own hint, not a filter-refusal notice.
func TestFamilyHintNeverClearsARefusal(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	m.runtime.setProbeManager(newSelectionManager())
	m.setGlobalFilter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: overLongComm()}})
	next, _ := m.cycleFamilyScope(+1) // refused: the comm pattern is unusable
	m = next.(*Model)
	m.refreshFamilyHint()
	if !showsRefusal(t, m) {
		t.Fatal("refreshFamilyHint erased the refusal notice")
	}
}

// refusedWhileScopedToNetwork returns a wide dashboard scoped to the untraced
// Network family (so the "not traced" hint shows) on which a filter was then
// refused - the state in which the kp2 bug struck. The width fits the refusal
// and the hint side by side.
func refusedWhileScopedToNetwork(t *testing.T) (*Model, *selectionProbeManager) {
	t.Helper()
	m, _ := newLiveSwapModel(t)
	m = resized(t, m, 300)
	manager := newSelectionManager()
	m.runtime.setProbeManager(manager)
	m = cycleTo(t, m, "Network")
	refused := m.filters.current().Clone()
	refused.Comm = &globalfilter.StringFilter{Pattern: overLongComm()}
	next, _ := m.Update(messages.GlobalFilterRequestedMsg{Filter: refused})
	m = next.(*Model)
	if !showsRefusal(t, m) {
		t.Fatalf("setup: expected a refusal notice, got:\n%s", m.View().Content)
	}
	return m, manager
}

// resized sends m a window size of width columns, which is what sizes the
// dashboard chrome (m.width alone does not).
func resized(t *testing.T, m *Model, width int) *Model {
	t.Helper()
	next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: 40})
	return next.(*Model)
}

// TestProbeChangeKeepsARefusalVisible is the kp2 regression: every probe
// change refreshes the family hint, and while the dashboard is scoped to an
// untraced family that refresh used to write the hint into the filter notice,
// replacing a refusal the user had not read yet. Both notices now show.
func TestProbeChangeKeepsARefusalVisible(t *testing.T) {
	for _, tc := range []struct {
		name    string
		session func(m *Model) uint64
	}{
		{"current session", func(m *Model) uint64 { return m.tracer.session }},
		{"stale session", func(m *Model) uint64 { return m.tracer.session + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := refusedWhileScopedToNetwork(t)
			next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "read", Session: tc.session(m)})
			m = next.(*Model)
			view := m.View().Content
			if !strings.Contains(view, "FILTER REFUSED") {
				t.Fatalf("the probe change erased the refusal notice:\n%s", view)
			}
			if !strings.Contains(view, "Network not traced") {
				t.Fatalf("expected the hint next to the refusal, got:\n%s", view)
			}
		})
	}
}

// TestFamilyHintNeverCrowdsOutARefusal: on a row too narrow for both, the
// hint is the one trimmed - the refusal is read first and must survive.
func TestFamilyHintNeverCrowdsOutARefusal(t *testing.T) {
	m, _ := refusedWhileScopedToNetwork(t)
	m = resized(t, m, 100)
	m.refreshFamilyHint()
	if view := m.View().Content; !strings.Contains(view, "keeping the previous filter") {
		t.Fatalf("the hint pushed the refusal off the status row:\n%s", view)
	}
}

// TestFamilyHintOutlivesAClearedRefusal: accepting a filter clears the
// refusal but, with the scope still on untraced Network, not the hint; the
// hint goes once the family gets a probe attached.
func TestFamilyHintOutlivesAClearedRefusal(t *testing.T) {
	m, manager := refusedWhileScopedToNetwork(t)
	accepted := m.filters.current().Clone()
	accepted.Comm = &globalfilter.StringFilter{Pattern: "firefox"}
	next, _ := m.Update(messages.GlobalFilterRequestedMsg{Filter: accepted})
	m = next.(*Model)
	view := m.View().Content
	if strings.Contains(view, "FILTER REFUSED") || !strings.Contains(view, "Network not traced") {
		t.Fatalf("expected only the hint after an accepted filter, got:\n%s", view)
	}

	manager.setActive("connect", true)
	next, _ = m.Update(probes.ProbeToggledMsg{Syscall: "connect", Session: m.tracer.session})
	m = next.(*Model)
	if view := m.View().Content; strings.Contains(view, "not traced") {
		t.Fatalf("expected the hint to go once Network is attached, got:\n%s", view)
	}
}

// TestUndoClearsTheFamilyHint: the hint follows the filter on screen, so
// undoing a pushed Network scope takes the hint with it.
func TestUndoClearsTheFamilyHint(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	m.runtime.setProbeManager(newSelectionManager())
	network := globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: "Network"}}
	next, _ := m.Update(messages.GlobalFilterRequestedMsg{Filter: network})
	m = next.(*Model)
	if view := m.View().Content; !strings.Contains(view, "Network not traced") {
		t.Fatalf("setup: expected the hint for a pushed Network scope, got:\n%s", view)
	}
	next, _ = m.undoGlobalFilter()
	m = next.(*Model)
	if view := m.View().Content; strings.Contains(view, "not traced") {
		t.Fatalf("expected undo to clear the hint with the scope, got:\n%s", view)
	}
}

// TestProbeChangeCarriesAttachedSetIntoRestart pins restart persistence: once
// the user changes probes at runtime, the next session's request carries the
// attached set, instead of reverting to the startup selection (nil).
func TestProbeChangeCarriesAttachedSetIntoRestart(t *testing.T) {
	requests := make(chan TraceRequest, 4)
	m := NewModel(-1, func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(m.tracer.stop)

	m.beginTraceCmd()()
	if req := <-requests; req.AttachSyscalls != nil {
		t.Fatalf("first session AttachSyscalls = %v, want nil (startup selection)", req.AttachSyscalls)
	}

	manager := newSelectionManager()
	manager.setActive("socket", true)
	m.runtime.setProbeManager(manager)
	next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "socket", Session: m.tracer.session})
	m = next.(*Model)

	m.beginTraceCmd()()
	if req := <-requests; !slices.Equal(req.AttachSyscalls, []string{"read", "socket"}) {
		t.Fatalf("restart AttachSyscalls = %v, want [read socket]", req.AttachSyscalls)
	}
}

// TestProbeSelectionKeptWhenNoManagerIsPublished: a change that races a
// restart finds no manager; the previous selection must survive rather than
// being replaced by an empty ("attach nothing") one.
func TestProbeSelectionKeptWhenNoManagerIsPublished(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	m.tracer.beginCmd(m.runtime, m.filters.current())
	t.Cleanup(m.tracer.stop)
	m.tracer.setAttachSyscalls([]string{"read"})
	next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "read", Session: m.tracer.session})
	m = next.(*Model)
	if !slices.Equal(m.tracer.attachSyscalls, []string{"read"}) {
		t.Fatalf("attachSyscalls = %v, want [read] kept", m.tracer.attachSyscalls)
	}
}

// TestDetachingEverythingCarriesAnEmptySelection: all probes detached is a
// real selection ("attach nothing"), distinct from nil ("startup flags").
func TestDetachingEverythingCarriesAnEmptySelection(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	manager := newSelectionManager()
	manager.setActive("read", false)
	m.tracer.beginCmd(m.runtime, m.filters.current())
	t.Cleanup(m.tracer.stop)
	m.runtime.setProbeManager(manager)
	next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "read", Session: m.tracer.session})
	m = next.(*Model)
	if m.tracer.attachSyscalls == nil || len(m.tracer.attachSyscalls) != 0 {
		t.Fatalf("attachSyscalls = %#v, want a non-nil empty selection", m.tracer.attachSyscalls)
	}
}
