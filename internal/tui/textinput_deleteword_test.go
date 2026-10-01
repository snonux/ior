package tui

import (
	"context"
	"strings"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/tui/probes"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// Task kz2: bubbles' textinput (v2.0.0 .. at least v2.2.1) panics on a
// delete-word-forward (Alt+D, Alt+Delete) with the cursor on the value's last
// rune: deleteWordForward steps past that rune and reads one past the value.
// Every text input of the TUI was exposed. Each host now feeds its input
// through common.UpdateTextInput, which turns that press into Delete (the
// same edit), and textinput_hosts_test.go in internal/tui/common keeps new
// hosts from calling textinput.Update directly. These tests drive every host
// end to end through Model.Update, the way a terminal key press arrives, so a
// host that bypasses the helper panics here.

// textInputHost opens one text input of the TUI, focused, on a fresh model.
type textInputHost struct {
	name string
	open func(t *testing.T) *Model
}

func textInputHosts() []textInputHost {
	return []textInputHost{
		{name: "pid picker", open: func(*testing.T) *Model {
			return NewModel(-1, func(context.Context, TraceRequest) error { return nil })
		}},
		{name: "flame search", open: func(t *testing.T) *Model {
			return press(t, newTypingTestModel(), text("/"))
		}},
		{name: "stream search", open: func(t *testing.T) *Model {
			return press(t, press(t, newTypingTestModel(), text("7")), text("/"))
		}},
		{name: "stream export", open: func(t *testing.T) *Model {
			m := press(t, newTypingTestModel(), text("7"))
			m = press(t, m, text(" ")) // X is only active while paused
			return press(t, m, text("X"))
		}},
		{name: "probes search", open: func(t *testing.T) *Model {
			m := newTypingTestModel()
			m.probeModal = probes.NewModel(fakeProbeManager{
				states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
			}).Open()
			return press(t, m, text("/"))
		}},
		{name: "record modal", open: func(t *testing.T) *Model {
			return press(t, newTypingTestModel(), text("R"))
		}},
		{name: "filter modal", open: func(t *testing.T) *Model {
			return openFileFilterEdit(t, newTypingTestModel())
		}},
	}
}

// deleteWordForwardPresses are the two presses bubbles binds to
// delete-word-forward, as Bubble Tea delivers them.
var deleteWordForwardPresses = []struct {
	name  string
	press tea.KeyPressMsg
}{
	{name: "alt+d", press: tea.KeyPressMsg{Code: 'd', Mod: tea.ModAlt}},
	{name: "alt+delete", press: tea.KeyPressMsg{Code: tea.KeyDelete, Mod: tea.ModAlt}},
}

// pressNoPanic is press, but turns a panic in Update into a failure of this
// subtest, so one panicking host does not abort the run and hide the others.
func pressNoPanic(t *testing.T, m *Model, k tea.KeyPressMsg) *Model {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", k.String(), r)
		}
	}()
	return press(t, m, k)
}

// requireInputShows fails unless the view, with its styling stripped (the
// cursor cell splits the value into differently styled runs), shows want and,
// when gone is set, not gone.
func requireInputShows(t *testing.T, m *Model, want, gone string) {
	t.Helper()
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, want) || (gone != "" && strings.Contains(view, gone)) {
		t.Fatalf("expected the input to show %q and not %q, view:\n%s", want, gone, view)
	}
}

// typeAndMoveLeft opens host, pastes value into its input and presses Left
// `left` times.
func typeAndMoveLeft(t *testing.T, host textInputHost, value string, left int) *Model {
	t.Helper()
	m := paste(host.open(t), value)
	for range left {
		m = press(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
	}
	return m
}

// TestDeleteWordForwardOnTheLastRuneInEveryTextInput pastes a value into
// every host, moves the cursor onto its last rune and presses Alt+D or
// Alt+Delete: before task kz2 every host but the two stream modals (guarded
// since task 9z2) panicked; now the last rune goes. The values start with
// "kz" so the view check cannot match other text, and one ends in wide
// runes, which the textinput counts per rune, not per byte or cell.
func TestDeleteWordForwardOnTheLastRuneInEveryTextInput(t *testing.T) {
	values := []struct{ typed, want string }{
		{typed: "kzqab", want: "kzqa"},
		{typed: "kz日本", want: "kz日"},
	}
	for _, host := range textInputHosts() {
		for _, del := range deleteWordForwardPresses {
			for _, v := range values {
				t.Run(host.name+"/"+del.name+"/"+v.typed, func(t *testing.T) {
					m := typeAndMoveLeft(t, host, v.typed, 1)
					m = pressNoPanic(t, m, del.press)
					requireInputShows(t, m, v.want, v.typed)
				})
			}
		}
	}
}

// TestDeleteWordForwardOnASingleRuneInEveryTextInput is the shortest value
// with the cursor on its last rune: one (wide) rune, cursor at 0, which
// panicked like the longer values. Only the absence of a panic is checked:
// an empty input is hard to tell from the rest of the view, and the record
// modal starts with a prefilled path, so there the rune is the last of a
// longer value. The resulting value is pinned by internal/tui/common's
// textinput_test.go.
func TestDeleteWordForwardOnASingleRuneInEveryTextInput(t *testing.T) {
	for _, host := range textInputHosts() {
		for _, del := range deleteWordForwardPresses {
			t.Run(host.name+"/"+del.name, func(t *testing.T) {
				_ = pressNoPanic(t, typeAndMoveLeft(t, host, "語", 1), del.press)
			})
		}
	}
}

// TestDeleteWordForwardAwayFromTheLastRuneInEveryTextInput are the negative
// controls: mid-value the press keeps its bubbles meaning and deletes up to
// the end of the next word, and with the cursor after the value (where
// bubbles returns early and never panicked) it deletes nothing.
func TestDeleteWordForwardAwayFromTheLastRuneInEveryTextInput(t *testing.T) {
	for _, host := range textInputHosts() {
		for _, del := range deleteWordForwardPresses {
			t.Run(host.name+"/"+del.name+"/mid-value", func(t *testing.T) {
				m := typeAndMoveLeft(t, host, "kzx foo bar", len(" foo bar"))
				m = pressNoPanic(t, m, del.press)
				requireInputShows(t, m, "kzx bar", "foo")
			})
			t.Run(host.name+"/"+del.name+"/at the end", func(t *testing.T) {
				m := pressNoPanic(t, typeAndMoveLeft(t, host, "kzx foo", 0), del.press)
				requireInputShows(t, m, "kzx foo", "")
			})
		}
	}
}
