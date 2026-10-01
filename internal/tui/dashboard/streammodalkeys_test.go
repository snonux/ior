package dashboard

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// TestStreamSearchModalGetsRealEditingKeys drives the dashboard the way the
// terminal does: with the Stream search modal open, Ctrl+X must type nothing
// and Ctrl+A must move to the start of the input, so typing "z" afterwards
// prepends it. Before task 9z2 the stream handed the modal the key's name as
// a press whose Text was that name: Ctrl+A still acted as Ctrl+A (the
// textinput binds "ctrl+a" and matches on that text), but the unbound Ctrl+X
// was typed as "ctrl+x". Only the Ctrl+X half pins changed behaviour; the
// Ctrl+A half is a regression guard.
func TestStreamSearchModalGetsRealEditingKeys(t *testing.T) {
	m := newFitModel(t, fitCase{tab: TabStream}, false, 100, 30)
	m = pressStreamKey(t, m, '/')
	if !m.streamModel.SearchModalVisible() {
		t.Fatal("/ did not open the search modal")
	}
	presses := []tea.KeyPressMsg{
		{Code: 'a', Text: "a"},
		{Code: 'b', Text: "b"},
		{Code: 'x', Mod: tea.ModCtrl},
		{Code: 'a', Mod: tea.ModCtrl},
		{Code: 'z', Text: "z"},
	}
	for _, press := range presses {
		next, _ := m.Update(press)
		m = next.(*Model)
	}
	if !m.streamModel.SearchModalVisible() {
		t.Fatal("the search modal closed while editing")
	}
	out := ansi.Strip(m.View().Content)
	if !strings.Contains(out, "/zab") || strings.Contains(out, "ctrl") {
		t.Fatalf("search input does not read \"zab\":\n%s", out)
	}
}

// TestStreamSearchModalMovesByWordWithRealPresses pins the HandleTeaKey route
// with key presses built the way Bubble Tea delivers them (Code plus Mod, no
// Text for a modified key), independent of eventstream's keyMsgFromString.
// Ctrl+Left and Alt+Left must jump to the start of "baz" and Ctrl+Right and
// Alt+Right to the end of "foo", so a typed "X" lands there; Ctrl+X must type
// nothing. Before task 9z2 HandleTeaKey sent Left/Right to HandleKey("left")
// or HandleKey("right") and dropped the modifier (one rune, not a word), and
// typed the unbound Ctrl+X as "ctrl+x": every case here pins changed
// behaviour and fails on the pre-9z2 tree. The four word-move cases also fail
// if only the open-modal shortcut in HandleTeaKey is removed (the Ctrl+X case
// then still passes through HandleKey's name route).
func TestStreamSearchModalMovesByWordWithRealPresses(t *testing.T) {
	home := tea.KeyPressMsg{Code: tea.KeyHome}
	tests := []struct {
		name  string
		keys  []tea.KeyPressMsg
		input string
	}{
		{name: "ctrl+left", keys: []tea.KeyPressMsg{{Code: tea.KeyLeft, Mod: tea.ModCtrl}}, input: "/foo bar Xbaz"},
		{name: "alt+left", keys: []tea.KeyPressMsg{{Code: tea.KeyLeft, Mod: tea.ModAlt}}, input: "/foo bar Xbaz"},
		{name: "ctrl+right", keys: []tea.KeyPressMsg{home, {Code: tea.KeyRight, Mod: tea.ModCtrl}}, input: "/fooX bar baz"},
		{name: "alt+right", keys: []tea.KeyPressMsg{home, {Code: tea.KeyRight, Mod: tea.ModAlt}}, input: "/fooX bar baz"},
		{name: "ctrl+x", keys: []tea.KeyPressMsg{{Code: 'x', Mod: tea.ModCtrl}}, input: "/foo bar bazX"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newFitModel(t, fitCase{tab: TabStream}, false, 100, 30)
			m = pressStreamKey(t, m, '/')
			if !m.streamModel.SearchModalVisible() {
				t.Fatal("/ did not open the search modal")
			}
			presses := typedPresses("foo bar baz")
			presses = append(presses, tt.keys...)
			presses = append(presses, tea.KeyPressMsg{Code: 'X', Text: "X"})
			for _, press := range presses {
				next, _ := m.Update(press)
				m = next.(*Model)
			}
			if !m.streamModel.SearchModalVisible() {
				t.Fatal("the search modal closed while editing")
			}
			out := ansi.Strip(m.View().Content)
			if !strings.Contains(out, tt.input) {
				t.Fatalf("search input does not read %q:\n%s", tt.input, out)
			}
		})
	}
}

// typedPresses is text as the key presses a terminal sends for it: a space
// is the Space key carrying " ", any other rune its own code and text.
func typedPresses(text string) []tea.KeyPressMsg {
	presses := make([]tea.KeyPressMsg, 0, len(text))
	for _, r := range text {
		if r == ' ' {
			presses = append(presses, tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
			continue
		}
		presses = append(presses, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	return presses
}
