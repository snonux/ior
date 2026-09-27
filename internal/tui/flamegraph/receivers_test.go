package flamegraph

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestInitDoesNotMutateModel pins that Init is side-effect free: it starts
// nothing (the dashboard drives refreshes and animation) and leaves the
// rendered model unchanged.
func TestInitDoesNotMutateModel(t *testing.T) {
	m := NewModel(nil)
	m.width, m.height = 80, 24
	m.anim.frames = []tuiFrame{{Name: "alpha", Path: "root" + pathSeparator + "alpha"}}
	beforeView := m.View().Content
	beforeGen, beforeInFlight := m.refreshGeneration, m.refreshInFlight

	if cmd := m.Init(); cmd != nil {
		t.Fatal("Init must not schedule anything")
	}
	if m.View().Content != beforeView || m.refreshGeneration != beforeGen || m.refreshInFlight != beforeInFlight {
		t.Fatal("Init mutated the model")
	}
}

// TestSearchInputReturnsTextInputCmd pins that a key typed into the search
// box returns the text input's command (its cursor blink) instead of
// dropping it, while esc and enter, which never reach the text input,
// return none.
func TestSearchInputReturnsTextInputCmd(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{{Name: "alpha", Path: "root" + pathSeparator + "alpha"}}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: '/', Text: "/"})
	if !m.search.isActive() {
		t.Fatal("precondition: '/' must open search mode")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'a', Text: "a"})
	m = next.(*Model)
	if cmd == nil {
		t.Fatal("typing into the search box dropped the text input's command")
	}

	if _, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter}); cmd != nil {
		t.Fatal("enter returned a command, want none")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: '/', Text: "/"})
	if _, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc}); cmd != nil {
		t.Fatal("esc returned a command, want none")
	}
}
