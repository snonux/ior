package probes

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

type fakeManager struct {
	// mu guards states: family batches mutate them from their own goroutine.
	mu         sync.Mutex
	states     []probemanager.ProbeState
	toggles    []string
	changes    []string
	failAttach map[string]bool
}

func (f *fakeManager) States() []probemanager.ProbeState {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]probemanager.ProbeState, len(f.states))
	copy(out, f.states)
	return out
}

func (f *fakeManager) Toggle(syscall string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.toggles = append(f.toggles, syscall)
	for i := range f.states {
		if f.states[i].Syscall == syscall {
			f.states[i].Active = !f.states[i].Active
		}
	}
	return nil
}

// Attach and Detach set the named probe's state and record the call in
// changes as "+name" / "-name".
func (f *fakeManager) Attach(syscall string) error { return f.set(syscall, true) }
func (f *fakeManager) Detach(syscall string) error { return f.set(syscall, false) }

func (f *fakeManager) set(syscall string, active bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	sign := "-"
	if active {
		sign = "+"
	}
	f.changes = append(f.changes, sign+syscall)
	for i := range f.states {
		if f.states[i].Syscall == syscall {
			f.states[i].Active = active
		}
	}
	return nil
}

// AttachFamily activates the family's inactive probes one by one, reporting
// progress after each like the real manager. failAttach names probes whose
// attach fails.
func (f *fakeManager) AttachFamily(_ context.Context, family types.SyscallFamily, progress func(int, int)) (probemanager.BatchResult, error) {
	return f.setFamily(family, true, progress), nil
}

// DetachFamily deactivates the family's active probes.
func (f *fakeManager) DetachFamily(_ context.Context, family types.SyscallFamily, progress func(int, int)) (probemanager.BatchResult, error) {
	return f.setFamily(family, false, progress), nil
}

func (f *fakeManager) setFamily(family types.SyscallFamily, active bool, progress func(int, int)) probemanager.BatchResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	var idx []int
	for i := range f.states {
		if f.states[i].Active != active && probemanager.SyscallFamily(f.states[i].Syscall) == family {
			idx = append(idx, i)
		}
	}
	result := probemanager.BatchResult{Total: len(idx)}
	progress(0, result.Total)
	for n, i := range idx {
		if active && f.failAttach[f.states[i].Syscall] {
			result.Errors = append(result.Errors, probemanager.SyscallError{Syscall: f.states[i].Syscall, Err: errors.New("no tracepoint")})
		} else {
			f.states[i].Active = active
			result.Changed++
		}
		progress(n+1, result.Total)
	}
	return result
}

func (f *fakeManager) ActiveCount() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	active := 0
	for _, s := range f.states {
		if s.Active {
			active++
		}
	}
	return active, len(f.states)
}

func TestOpenRefreshesFromManager(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm)
	m = m.Open()
	if len(m.probes) != 1 || m.probes[0].Syscall != "read" {
		t.Fatalf("unexpected probes after first open: %+v", m.probes)
	}

	fm.states = append(fm.states, probemanager.ProbeState{Syscall: "write", Active: true})
	m = m.Close().Open()
	if len(m.probes) != 2 {
		t.Fatalf("expected probes refreshed on open, got %+v", m.probes)
	}
}

func TestToggleEmitsProbeToggledMsg(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm).Open()
	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{' '}[0], Text: string([]rune{' '})})
	if cmd == nil {
		t.Fatalf("expected toggle command")
	}
	msg := cmd()
	toggled, ok := msg.(ProbeToggledMsg)
	if !ok {
		t.Fatalf("expected ProbeToggledMsg, got %T", msg)
	}
	if toggled.Err != nil {
		t.Fatalf("unexpected toggle err: %v", toggled.Err)
	}
	if len(fm.toggles) != 1 || fm.toggles[0] != "read" {
		t.Fatalf("expected read toggle, got %+v", fm.toggles)
	}
	_ = next
}

// pressBulk presses a bulk key (a/n) in m and runs what the TUI does with the
// modal's request: the walk over every probe of fm, as SetAllCmd runs it. It
// returns the walk's result.
func pressBulk(t *testing.T, m Model, fm *fakeManager, key rune) ProbeToggledMsg {
	t.Helper()
	_, cmd := m.Update(tea.KeyPressMsg{Code: key, Text: string(key)})
	if cmd == nil {
		t.Fatalf("key %q returned no command", key)
	}
	request, ok := cmd().(SetAllRequestMsg)
	if !ok || request.Active != (key == 'a') {
		t.Fatalf("key %q yielded %#v, want a SetAllRequestMsg{Active: %v}", key, request, key == 'a')
	}
	toggled, ok := SetAllCmd(context.Background(), fm, request.Active, 7)().(ProbeToggledMsg)
	if !ok {
		t.Fatal("SetAllCmd did not yield a ProbeToggledMsg")
	}
	return toggled
}

func TestBulkKeysApplyGloballyNotOnlyFiltered(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{
			{Syscall: "read", Active: true},
			{Syscall: "write", Active: true},
			{Syscall: "openat", Active: true},
		},
	}
	m := NewModel(fm).Open()
	m.search = "read"

	if toggled := pressBulk(t, m, fm, 'n'); toggled.Err != nil || toggled.Session != 7 || toggled.Intent != nil {
		t.Fatalf("unexpected bulk off msg: %#v", toggled)
	}
	if want := []string{"-read", "-write", "-openat"}; !slices.Equal(fm.changes, want) {
		t.Fatalf("changes = %v, want all probes detached despite the filter %v", fm.changes, want)
	}

	fm.changes = nil
	pressBulk(t, NewModel(fm).Open(), fm, 'a')
	if want := []string{"+read", "+write", "+openat"}; !slices.Equal(fm.changes, want) {
		t.Fatalf("changes = %v, want %v", fm.changes, want)
	}
}

// TestBulkKeysAreIdempotent: a/n set a definite state from a fresh read of
// the manager, so they only change probes not yet in that state - even when
// the list the modal shows is stale - and repeating them changes nothing.
// With Toggle they used to flip probes that had changed since the modal
// loaded its list.
func TestBulkKeysAreIdempotent(t *testing.T) {
	fm := &fakeManager{states: []probemanager.ProbeState{
		{Syscall: "read", Active: true}, {Syscall: "write"},
	}}
	m := NewModel(fm).Open()   // the modal's list: read on, write off
	fm.states[1].Active = true // write attached meanwhile (stale list)
	pressBulk(t, m, fm, 'a')
	if len(fm.changes) != 0 {
		t.Fatalf("a with everything attached changed %v, want nothing", fm.changes)
	}
	for range 2 {
		pressBulk(t, m, fm, 'n')
	}
	if want := []string{"-read", "-write"}; !slices.Equal(fm.changes, want) {
		t.Fatalf("changes = %v, want each probe detached once %v", fm.changes, want)
	}
}

// TestSetAllCmdStopsWhenItsSessionEnds: the walk runs on the trace session's
// context, so a restart stops it before the next probe instead of attaching
// the rest to a manager that is about to close. The result still arrives,
// tagged with the session and carrying the cancellation.
func TestSetAllCmdStopsWhenItsSessionEnds(t *testing.T) {
	fm := &fakeManager{states: []probemanager.ProbeState{{Syscall: "read"}, {Syscall: "write"}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	toggled, ok := SetAllCmd(ctx, fm, true, 3)().(ProbeToggledMsg)
	if !ok || !errors.Is(toggled.Err, context.Canceled) || toggled.Session != 3 {
		t.Fatalf("result = %#v, want the cancellation tagged with session 3", toggled)
	}
	if len(fm.changes) != 0 {
		t.Fatalf("a cancelled walk still changed %v", fm.changes)
	}
}

func TestNavigationKeepsCursorInsideScrolledWindow(t *testing.T) {
	states := make([]probemanager.ProbeState, 0, 60)
	for i := 0; i < 60; i++ {
		states = append(states, probemanager.ProbeState{Syscall: fmt.Sprintf("sys_%02d", i), Active: true})
	}
	m := NewModel(&fakeManager{states: states}).SetSize(100, 24).Open()
	for i := 0; i < 30; i++ {
		m, _ = m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	if m.cursor != 30 {
		t.Fatalf("expected cursor 30, got %d", m.cursor)
	}
	rows := m.visibleRows()
	if m.cursor < m.offset || m.cursor >= m.offset+rows {
		t.Fatalf("expected cursor %d inside window [%d,%d)", m.cursor, m.offset, m.offset+rows)
	}
	if view := m.View(100, 24); !strings.Contains(view, "sys_30") {
		t.Fatalf("expected selected probe sys_30 to be rendered")
	}
	for i := 0; i < 30; i++ {
		m, _ = m.Update(tea.KeyPressMsg{Code: 'k', Text: "k"})
	}
	if m.cursor != 0 || m.offset != 0 {
		t.Fatalf("expected cursor and offset back at 0, got cursor=%d offset=%d", m.cursor, m.offset)
	}
}

// Task 4r2: a terminal paste is one tea.PasteMsg; the search line must take it
// and narrow the list the way typed text does.
func TestSearchLineAcceptsBracketedPaste(t *testing.T) {
	fm := &fakeManager{states: []probemanager.ProbeState{{Syscall: "read"}, {Syscall: "write"}}}
	m := NewModel(fm).Open()
	m, _ = m.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
	if !m.TextInputFocused() {
		t.Fatalf("expected / to open the search line")
	}
	m, _ = m.Update(tea.PasteMsg{Content: "wri"})
	if m.search != "wri" || len(m.filtered()) != 1 || m.filtered()[0].Syscall != "write" {
		t.Fatalf("expected the pasted text to filter to write, search=%q rows=%v", m.search, m.filtered())
	}
}

// With the search line closed the list keys are commands (a all-on, n all-off,
// q close), so a paste must not run them nor open the search line.
func TestBracketedPasteWithoutSearchLineIsIgnored(t *testing.T) {
	fm := &fakeManager{states: []probemanager.ProbeState{{Syscall: "read"}}}
	m := NewModel(fm).Open()
	m, cmd := m.Update(tea.PasteMsg{Content: "an/q"})
	if cmd != nil || m.TextInputFocused() || m.search != "" || !m.Visible() || len(fm.toggles)+len(fm.changes) != 0 {
		t.Fatalf("paste acted as keys: cmd=%v focused=%v search=%q visible=%v toggles=%v changes=%v",
			cmd != nil, m.TextInputFocused(), m.search, m.Visible(), fm.toggles, fm.changes)
	}
}
