package probes

import (
	"testing"

	"ior/internal/probemanager"

	tea "github.com/charmbracelet/bubbletea"
)

type fakeManager struct {
	states  []probemanager.ProbeState
	toggles []string
}

func (f *fakeManager) States() []probemanager.ProbeState {
	out := make([]probemanager.ProbeState, len(f.states))
	copy(out, f.states)
	return out
}

func (f *fakeManager) Toggle(syscall string) error {
	f.toggles = append(f.toggles, syscall)
	for i := range f.states {
		if f.states[i].Syscall == syscall {
			f.states[i].Active = !f.states[i].Active
		}
	}
	return nil
}

func (f *fakeManager) ActiveCount() (int, int) {
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
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
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

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if cmd == nil {
		t.Fatalf("expected bulk off command")
	}
	msg := cmd()
	if toggled, ok := msg.(ProbeToggledMsg); !ok || toggled.Err != nil {
		t.Fatalf("unexpected bulk off msg: %#v", msg)
	}
	if len(fm.toggles) != 3 {
		t.Fatalf("expected all probes toggled off despite filter, got toggles=%+v", fm.toggles)
	}

	// Re-open with all inactive and filtered search still present; "a" should
	// toggle all probes back on.
	m = NewModel(fm).Open()
	m.search = "read"
	fm.toggles = nil
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if cmd == nil {
		t.Fatalf("expected bulk on command")
	}
	msg = cmd()
	if toggled, ok := msg.(ProbeToggledMsg); !ok || toggled.Err != nil {
		t.Fatalf("unexpected bulk on msg: %#v", msg)
	}
	if len(fm.toggles) != 3 {
		t.Fatalf("expected all probes toggled on despite filter, got toggles=%+v", fm.toggles)
	}
}
