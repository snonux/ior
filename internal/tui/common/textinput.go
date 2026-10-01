package common

import (
	"unicode/utf8"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// UpdateTextInput is the one way every TUI screen feeds a message to its
// bubbles textinput: ti.Update(msg) with the delete-word-forward crash
// guarded (guardDeleteWordForward). Call it instead of ti.Update, which
// internal/tui/common/textinput_hosts_test.go enforces for every textinput
// host under internal/tui (task kz2).
func UpdateTextInput(ti textinput.Model, msg tea.Msg) (textinput.Model, tea.Cmd) {
	return ti.Update(guardDeleteWordForward(ti, msg))
}

// guardDeleteWordForward returns msg for ti, except that a
// delete-word-forward press (ti.KeyMap.DeleteWordForward: Alt+D,
// Alt+Delete) with the cursor on the value's last rune becomes a plain
// Delete. bubbles' textinput.deleteWordForward (v2.0.0 up to at least v2.2.1,
// the newest release when task kz2 checked, so upgrading does not help)
// advances the cursor past that rune and then reads m.value[m.pos], one past
// the end, and panics. Delete removes exactly the rune delete-word-forward
// would remove there (the rest of the word is that one rune), and so does the
// deleteAfterCursor route bubbles takes for a masked (EchoPassword/EchoNone)
// input, so the rewrite never changes what the key does, it only avoids the
// crash. Every other cursor position (mid-value, at the end, empty value) and
// every other message passes through unchanged. The position is counted in
// runes, as textinput.Position and the textinput's []rune value are, so wide
// and multi-byte runes are handled alike.
//
// Task 9z2 introduced this guard for the stream search/export modals only
// (as eventstream.guardDeleteWordForward); task kz2 moved it here for every
// textinput.
func guardDeleteWordForward(ti textinput.Model, msg tea.Msg) tea.Msg {
	press, ok := msg.(tea.KeyPressMsg)
	if !ok || !key.Matches(press, ti.KeyMap.DeleteWordForward) {
		return msg
	}
	if ti.Position() != utf8.RuneCountInString(ti.Value())-1 {
		return msg
	}
	return tea.KeyPressMsg{Code: tea.KeyDelete}
}
