package common

import (
	"testing"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

var (
	altD      = tea.KeyPressMsg{Code: 'd', Mod: tea.ModAlt}
	altDelete = tea.KeyPressMsg{Code: tea.KeyDelete, Mod: tea.ModAlt}
)

// focusedInput is a focused textinput holding value with the cursor at pos
// (in runes).
func focusedInput(value string, pos int) textinput.Model {
	ti := textinput.New()
	ti.Focus()
	ti.SetValue(value)
	ti.SetCursor(pos)
	return ti
}

// TestUpdateTextInputDeleteWordForward pins what Alt+D and Alt+Delete do
// through UpdateTextInput (task kz2). The "last rune" cases panicked in
// bubbles' deleteWordForward and are now a Delete of that rune; the others
// are the negative controls, where the press passes through unchanged and
// keeps bubbles' meaning.
func TestUpdateTextInputDeleteWordForward(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		pos     int
		echo    textinput.EchoMode
		want    string
		wantPos int
	}{
		{name: "last rune", value: "ab", pos: 1, want: "a", wantPos: 1},
		{name: "last rune of words", value: "foo bar", pos: 6, want: "foo ba", wantPos: 6},
		{name: "single rune", value: "x", pos: 0, want: "", wantPos: 0},
		{name: "wide last rune", value: "日本", pos: 1, want: "日", wantPos: 1},
		{name: "single wide rune", value: "語", pos: 0, want: "", wantPos: 0},
		{name: "trailing space as last rune", value: "a ", pos: 1, want: "a", wantPos: 1},
		{name: "masked last rune", value: "ab", pos: 1, echo: textinput.EchoPassword, want: "a", wantPos: 1},
		{name: "mid-value deletes the next word", value: "foo bar baz", pos: 3, want: "foo baz", wantPos: 3},
		{name: "at the start", value: "foo bar", pos: 0, want: " bar", wantPos: 0},
		{name: "at the end", value: "ab", pos: 2, want: "ab", wantPos: 2},
		{name: "empty", value: "", pos: 0, want: "", wantPos: 0},
	}
	for _, tc := range cases {
		for _, press := range []tea.KeyPressMsg{altD, altDelete} {
			t.Run(tc.name+"/"+press.String(), func(t *testing.T) {
				ti := focusedInput(tc.value, tc.pos)
				ti.EchoMode = tc.echo
				ti, _ = UpdateTextInput(ti, press)
				if ti.Value() != tc.want || ti.Position() != tc.wantPos {
					t.Fatalf("%q at %d: got %q at %d, want %q at %d",
						tc.value, tc.pos, ti.Value(), ti.Position(), tc.want, tc.wantPos)
				}
			})
		}
	}
}

// TestGuardDeleteWordForwardPassesEverythingElseThrough: only a
// delete-word-forward press on the last rune is rewritten; any other key
// there, and any non-key message, reaches the textinput as it came.
func TestGuardDeleteWordForwardPassesEverythingElseThrough(t *testing.T) {
	ti := focusedInput("ab", 1)
	msgs := []tea.Msg{
		tea.KeyPressMsg{Code: 'd', Text: "d"},
		tea.KeyPressMsg{Code: tea.KeyDelete},
		tea.KeyPressMsg{Code: tea.KeyBackspace, Mod: tea.ModAlt},
		tea.KeyReleaseMsg{Code: 'd', Mod: tea.ModAlt},
		tea.PasteMsg{Content: "x"},
	}
	for _, msg := range msgs {
		if got := guardDeleteWordForward(ti, msg); got != msg {
			t.Errorf("%#v was rewritten to %#v", msg, got)
		}
	}
	if got := guardDeleteWordForward(ti, altD); got != (tea.KeyPressMsg{Code: tea.KeyDelete}) {
		t.Errorf("alt+d on the last rune: got %#v, want Delete", got)
	}
}

// TestBubblesDeleteWordForwardStillPanicsOnTheLastRune is the reason for
// UpdateTextInput: it calls the bubbles textinput directly and expects the
// panic. When a bubbles upgrade fixes deleteWordForward this test fails;
// the guard (and textinput_hosts_test.go) can then be removed and hosts may
// call textinput.Update again.
func TestBubblesDeleteWordForwardStillPanicsOnTheLastRune(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("bubbles no longer panics on Alt+D on the last rune: " +
				"UpdateTextInput's guard is obsolete, see its comment")
		}
	}()
	ti := focusedInput("ab", 1)
	_, _ = ti.Update(altD)
}

// TestUpdateTextInputSwallowsTheClipboardPasteKey (task uz2): Ctrl+V used to
// make bubbles return a clipboard-read command that every host dropped, so the
// key did nothing and still ran a read. It is now swallowed up front - no
// command, no change - while terminal paste (tea.PasteMsg) and every other key
// keep working.
func TestUpdateTextInputSwallowsTheClipboardPasteKey(t *testing.T) {
	ti := focusedInput("abc", 3)
	ctrlV := tea.KeyPressMsg{Code: 'v', Mod: tea.ModCtrl}
	if _, cmd := ti.Update(ctrlV); cmd == nil {
		t.Fatal("setup: bubbles no longer answers Ctrl+V with a clipboard command; revisit isClipboardPaste")
	}
	got, cmd := UpdateTextInput(ti, ctrlV)
	if cmd != nil || got.Value() != "abc" || got.Position() != 3 {
		t.Fatalf("Ctrl+V: value %q pos %d cmd %v, want the input untouched and no command", got.Value(), got.Position(), cmd != nil)
	}

	pasted, _ := UpdateTextInput(ti, tea.PasteMsg{Content: "XY"})
	if pasted.Value() != "abcXY" {
		t.Fatalf("bracketed paste gave %q, want abcXY", pasted.Value())
	}
	typed, _ := UpdateTextInput(ti, tea.KeyPressMsg{Code: 'z', Text: "z"})
	if typed.Value() != "abcz" {
		t.Fatalf("typing gave %q, want abcz", typed.Value())
	}
}
