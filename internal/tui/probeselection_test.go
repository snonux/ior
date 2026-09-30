package tui

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/probemanager"
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
	// is closed, so a test can act while the batch is half done.
	hold chan struct{}
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

func (f *selectionProbeManager) AttachFamily(family types.SyscallFamily, progress func(int, int)) (probemanager.BatchResult, error) {
	return f.setFamily(family, true, progress), nil
}

func (f *selectionProbeManager) DetachFamily(family types.SyscallFamily, progress func(int, int)) (probemanager.BatchResult, error) {
	return f.setFamily(family, false, progress), nil
}

func (f *selectionProbeManager) setFamily(family types.SyscallFamily, active bool, progress func(int, int)) probemanager.BatchResult {
	var result probemanager.BatchResult
	for i := range f.states {
		f.mu.Lock()
		change := f.states[i].Active != active && probemanager.SyscallFamily(f.states[i].Syscall) == family
		if change {
			f.states[i].Active = active
			result.Total++
			result.Changed++
		}
		f.mu.Unlock()
		if change && result.Changed == 1 && f.hold != nil {
			<-f.hold
		}
	}
	progress(result.Total, result.Total)
	return result
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
