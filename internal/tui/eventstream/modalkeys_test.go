package eventstream

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestKeyMsgFromStringNamesKeys pins keyMsgFromString: every key name the
// modals' textinput binds (and the stream's page-key aliases) becomes that
// key's press, without text unless it is a plain rune or space, and the
// press spells the same name back. The old mapping knew only esc, enter, tab,
// up, down and space and typed every other name as text (task 9z2).
func TestKeyMsgFromStringNamesKeys(t *testing.T) {
	tests := []struct {
		name string
		want tea.KeyPressMsg
		// spelled is msg.String() when it differs from name (an alias).
		spelled string
	}{
		{name: "a", want: tea.KeyPressMsg{Code: 'a', Text: "a"}},
		{name: "A", want: tea.KeyPressMsg{Code: 'A', Text: "A"}},
		{name: "検", want: tea.KeyPressMsg{Code: '検', Text: "検"}},
		{name: "+", want: tea.KeyPressMsg{Code: '+', Text: "+"}},
		{name: " ", want: tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}, spelled: "space"},
		{name: "space", want: tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}},
		{name: "esc", want: tea.KeyPressMsg{Code: tea.KeyEsc}},
		{name: "enter", want: tea.KeyPressMsg{Code: tea.KeyEnter}},
		{name: "tab", want: tea.KeyPressMsg{Code: tea.KeyTab}},
		{name: "up", want: tea.KeyPressMsg{Code: tea.KeyUp}},
		{name: "down", want: tea.KeyPressMsg{Code: tea.KeyDown}},
		{name: "left", want: tea.KeyPressMsg{Code: tea.KeyLeft}},
		{name: "right", want: tea.KeyPressMsg{Code: tea.KeyRight}},
		{name: "home", want: tea.KeyPressMsg{Code: tea.KeyHome}},
		{name: "end", want: tea.KeyPressMsg{Code: tea.KeyEnd}},
		{name: "backspace", want: tea.KeyPressMsg{Code: tea.KeyBackspace}},
		{name: "delete", want: tea.KeyPressMsg{Code: tea.KeyDelete}},
		{name: "insert", want: tea.KeyPressMsg{Code: tea.KeyInsert}},
		{name: "pgup", want: tea.KeyPressMsg{Code: tea.KeyPgUp}},
		{name: "pageup", want: tea.KeyPressMsg{Code: tea.KeyPgUp}, spelled: "pgup"},
		{name: "pgdown", want: tea.KeyPressMsg{Code: tea.KeyPgDown}},
		{name: "pgdn", want: tea.KeyPressMsg{Code: tea.KeyPgDown}, spelled: "pgdown"},
		{name: "pagedown", want: tea.KeyPressMsg{Code: tea.KeyPgDown}, spelled: "pgdown"},
		{name: "ctrl+a", want: tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl}},
		{name: "ctrl+e", want: tea.KeyPressMsg{Code: 'e', Mod: tea.ModCtrl}},
		{name: "ctrl+b", want: tea.KeyPressMsg{Code: 'b', Mod: tea.ModCtrl}},
		{name: "ctrl+f", want: tea.KeyPressMsg{Code: 'f', Mod: tea.ModCtrl}},
		{name: "ctrl+h", want: tea.KeyPressMsg{Code: 'h', Mod: tea.ModCtrl}},
		{name: "ctrl+d", want: tea.KeyPressMsg{Code: 'd', Mod: tea.ModCtrl}},
		{name: "ctrl+k", want: tea.KeyPressMsg{Code: 'k', Mod: tea.ModCtrl}},
		{name: "ctrl+u", want: tea.KeyPressMsg{Code: 'u', Mod: tea.ModCtrl}},
		{name: "ctrl+w", want: tea.KeyPressMsg{Code: 'w', Mod: tea.ModCtrl}},
		{name: "ctrl+x", want: tea.KeyPressMsg{Code: 'x', Mod: tea.ModCtrl}},
		{name: "ctrl+left", want: tea.KeyPressMsg{Code: tea.KeyLeft, Mod: tea.ModCtrl}},
		{name: "ctrl+right", want: tea.KeyPressMsg{Code: tea.KeyRight, Mod: tea.ModCtrl}},
		{name: "ctrl+space", want: tea.KeyPressMsg{Code: tea.KeySpace, Mod: tea.ModCtrl}},
		{name: "alt+b", want: tea.KeyPressMsg{Code: 'b', Mod: tea.ModAlt}},
		{name: "alt+f", want: tea.KeyPressMsg{Code: 'f', Mod: tea.ModAlt}},
		{name: "alt+d", want: tea.KeyPressMsg{Code: 'd', Mod: tea.ModAlt}},
		{name: "alt+backspace", want: tea.KeyPressMsg{Code: tea.KeyBackspace, Mod: tea.ModAlt}},
		{name: "alt+delete", want: tea.KeyPressMsg{Code: tea.KeyDelete, Mod: tea.ModAlt}},
		{name: "ctrl+alt+b", want: tea.KeyPressMsg{Code: 'b', Mod: tea.ModCtrl | tea.ModAlt}},
		{name: "shift+tab", want: tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := keyMsgFromString(tt.name)
			if !ok {
				t.Fatalf("keyMsgFromString(%q) names no key", tt.name)
			}
			if got.Code != tt.want.Code || got.Mod != tt.want.Mod || got.Text != tt.want.Text {
				t.Fatalf("keyMsgFromString(%q) = %+v, want %+v", tt.name, got, tt.want)
			}
			spelled := tt.spelled
			if spelled == "" {
				spelled = tt.name
			}
			if got.String() != spelled {
				t.Fatalf("keyMsgFromString(%q).String() = %q, want %q", tt.name, got.String(), spelled)
			}
		})
	}
}

// TestKeyMsgFromStringRejectsNonKeys pins that a string naming no key is
// not a key (and so is never typed): unknown names, unknown modifiers, a
// modifier without a key and multi-rune text.
func TestKeyMsgFromStringRejectsNonKeys(t *testing.T) {
	for _, name := range []string{"", "f13", "ctrl+", "ctrl+foo", "foo+a", "ctrl+ctrl", "abc", "検索", "ctrl+x+"} {
		if got, ok := keyMsgFromString(name); ok {
			t.Errorf("keyMsgFromString(%q) = %+v, want no key", name, got)
		}
	}
}

// modalKeyEntry presses one named key on a stream Model through one of its
// two key entry points.
type modalKeyEntry struct {
	name  string
	press func(t *testing.T, m *Model, keyName string) bool
}

// modalKeyEntries are the stream Model's key entry points: HandleTeaKey, which
// the dashboard calls with the real key press, and HandleKey, which takes the
// key's name.
var modalKeyEntries = []modalKeyEntry{
	{name: "HandleTeaKey", press: func(t *testing.T, m *Model, keyName string) bool {
		t.Helper()
		msg, ok := keyMsgFromString(keyName)
		if !ok {
			t.Fatalf("test key %q names no key", keyName)
		}
		handled, _ := m.HandleTeaKey(msg)
		return handled
	}},
	{name: "HandleKey", press: func(t *testing.T, m *Model, keyName string) bool {
		t.Helper()
		handled, _ := m.HandleKey(keyName)
		return handled
	}},
}

// streamInputModal opens one of the stream Model's text-input modals with a
// value and reads its input back.
type streamInputModal struct {
	name  string
	open  func(m *Model, value string)
	state func(m *Model) (string, int)
}

var streamInputModals = []streamInputModal{
	{
		name: "search",
		open: func(m *Model, value string) { m.searchModal = m.searchModal.Open(SearchForward, value) },
		state: func(m *Model) (string, int) {
			return m.searchModal.textInput.Value(), m.searchModal.textInput.Position()
		},
	},
	{
		name: "export",
		open: func(m *Model, value string) { m.exportModal = m.exportModal.Open(value) },
		state: func(m *Model) (string, int) {
			return m.exportModal.textInput.Value(), m.exportModal.textInput.Position()
		},
	},
}

// modalEditKeyCases press keys on "foo bar baz" with the cursor at its end
// (Open's position) and give the input's value and cursor afterwards. Every
// key must reach the textinput as the key it names: before task 9z2 all but
// esc, enter, tab, up, down and space were typed as their names.
var modalEditKeyCases = []struct {
	name  string
	keys  []string
	value string
	pos   int
}{
	{name: "type rune", keys: []string{"x"}, value: "foo bar bazx", pos: 12},
	{name: "type space", keys: []string{"space"}, value: "foo bar baz ", pos: 12},
	{name: "ctrl+a", keys: []string{"ctrl+a"}, value: "foo bar baz", pos: 0},
	{name: "home", keys: []string{"home"}, value: "foo bar baz", pos: 0},
	{name: "ctrl+e", keys: []string{"ctrl+a", "ctrl+e"}, value: "foo bar baz", pos: 11},
	{name: "end", keys: []string{"home", "end"}, value: "foo bar baz", pos: 11},
	{name: "left", keys: []string{"left"}, value: "foo bar baz", pos: 10},
	{name: "right", keys: []string{"home", "right"}, value: "foo bar baz", pos: 1},
	{name: "ctrl+b", keys: []string{"ctrl+b"}, value: "foo bar baz", pos: 10},
	{name: "ctrl+f", keys: []string{"home", "ctrl+f"}, value: "foo bar baz", pos: 1},
	{name: "alt+b", keys: []string{"alt+b"}, value: "foo bar baz", pos: 8},
	{name: "ctrl+left", keys: []string{"ctrl+left"}, value: "foo bar baz", pos: 8},
	{name: "alt+f", keys: []string{"home", "alt+f"}, value: "foo bar baz", pos: 3},
	{name: "ctrl+right", keys: []string{"home", "ctrl+right"}, value: "foo bar baz", pos: 3},
	{name: "backspace", keys: []string{"backspace"}, value: "foo bar ba", pos: 10},
	{name: "ctrl+h", keys: []string{"ctrl+h"}, value: "foo bar ba", pos: 10},
	{name: "delete", keys: []string{"home", "delete"}, value: "oo bar baz", pos: 0},
	{name: "ctrl+d", keys: []string{"home", "ctrl+d"}, value: "oo bar baz", pos: 0},
	{name: "ctrl+k", keys: []string{"alt+b", "ctrl+k"}, value: "foo bar ", pos: 8},
	{name: "ctrl+u", keys: []string{"alt+b", "ctrl+u"}, value: "baz", pos: 0},
	{name: "ctrl+w", keys: []string{"ctrl+w"}, value: "foo bar ", pos: 8},
	{name: "alt+backspace", keys: []string{"alt+backspace"}, value: "foo bar ", pos: 8},
	{name: "alt+d mid-value", keys: []string{"home", "alt+d"}, value: " bar baz", pos: 0},
	// bubbles v2.0.0 panics on a delete-word-forward from the last rune
	// (task kz2); the modals turn it into Delete (guardDeleteWordForward).
	{name: "alt+d on the last rune", keys: []string{"left", "alt+d"}, value: "foo bar ba", pos: 10},
	{name: "alt+delete on the last rune", keys: []string{"left", "alt+delete"}, value: "foo bar ba", pos: 10},
	{name: "alt+d at the end", keys: []string{"alt+d"}, value: "foo bar baz", pos: 11},
	// Keys the textinput does not bind type nothing.
	{name: "ctrl+x", keys: []string{"ctrl+x"}, value: "foo bar baz", pos: 11},
	{name: "alt+x", keys: []string{"alt+x"}, value: "foo bar baz", pos: 11},
	{name: "ctrl+v", keys: []string{"ctrl+v"}, value: "foo bar baz", pos: 11},
	{name: "pgup", keys: []string{"pgup", "pgdown"}, value: "foo bar baz", pos: 11},
	{name: "insert", keys: []string{"insert"}, value: "foo bar baz", pos: 11},
}

// TestStreamModalsEditWithNamedKeys presses every editing key on the search
// and export modals through both key entry points and checks the input's
// value and cursor: the keys edit, unbound keys type nothing, typed runes
// still go in (task 9z2).
func TestStreamModalsEditWithNamedKeys(t *testing.T) {
	for _, modal := range streamInputModals {
		for _, entry := range modalKeyEntries {
			for _, tt := range modalEditKeyCases {
				t.Run(modal.name+"/"+entry.name+"/"+tt.name, func(t *testing.T) {
					m := NewModel(NewRingBuffer())
					m.SetViewport(80, 20)
					modal.open(&m, "foo bar baz")
					for _, k := range tt.keys {
						if !entry.press(t, &m, k) {
							t.Fatalf("%s(%q) not consumed by the open modal", entry.name, k)
						}
					}
					value, pos := modal.state(&m)
					if value != tt.value || pos != tt.pos {
						t.Fatalf("after %v: value %q cursor %d, want %q cursor %d", tt.keys, value, pos, tt.value, tt.pos)
					}
					if !m.inputModalVisible() {
						t.Fatalf("after %v the modal closed", tt.keys)
					}
				})
			}
		}
	}
}

// TestStreamModalsIgnoreUnknownKeyNames pins that HandleKey consumes a string
// naming no key while a modal is open, and neither types it nor passes it on.
func TestStreamModalsIgnoreUnknownKeyNames(t *testing.T) {
	for _, modal := range streamInputModals {
		for _, name := range []string{"f13", "ctrl+foo", "abc", "検索"} {
			m := NewModel(NewRingBuffer())
			m.SetViewport(80, 20)
			modal.open(&m, "foo")
			handled, cmd := m.HandleKey(name)
			if !handled || cmd != nil {
				t.Fatalf("%s: HandleKey(%q) = %v, %v; want consumed without a command", modal.name, name, handled, cmd)
			}
			if value, pos := modal.state(&m); value != "foo" || pos != 3 {
				t.Fatalf("%s: HandleKey(%q) left value %q cursor %d, want \"foo\" cursor 3", modal.name, name, value, pos)
			}
		}
	}
}

// TestHandleTeaKeyTypesComposedText pins that a key press carrying several
// runes of text (an IME composition) is typed whole into an open modal: the
// modal gets the press itself, not a name.
func TestHandleTeaKeyTypesComposedText(t *testing.T) {
	for _, modal := range streamInputModals {
		m := NewModel(NewRingBuffer())
		m.SetViewport(80, 20)
		modal.open(&m, "a")
		if handled, _ := m.HandleTeaKey(tea.KeyPressMsg{Code: tea.KeyExtended, Text: "検索"}); !handled {
			t.Fatalf("%s: composed text not consumed", modal.name)
		}
		if value, pos := modal.state(&m); value != "a検索" || pos != 3 {
			t.Fatalf("%s: value %q cursor %d, want \"a検索\" cursor 3", modal.name, value, pos)
		}
	}
}
