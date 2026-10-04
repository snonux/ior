package common

import (
	"unicode/utf8"

	"github.com/rivo/uniseg"

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
	if isClipboardPaste(ti, msg) {
		return ti, nil
	}
	before := ti.Position()
	ti, cmd := ti.Update(guardDeleteWordForward(ti, msg))
	snapCursorToGrapheme(&ti, before)
	return ti, cmd
}

// snapCursorToGrapheme keeps the cursor on a grapheme boundary (task pz2).
// bubbles moves and edits by rune, so Left/Right can leave the cursor between
// a base rune and its variation selector, ZWJ continuation or combining mark
// (the heart + U+FE0F emoji, a flag's two regional indicators). The cursor is
// then drawn over the lone continuation rune, which renders as a stray mark
// glued to the previous cell and which the terminal and ansi/lipgloss measure
// one cell wider than bubbles' per-rune width, so the input line outgrew its
// box. A cursor that landed inside a cluster is moved to its edge in the
// direction it was travelling (before is where it started): Left to the
// cluster's start, Right to its end, so one key press still crosses exactly
// one grapheme.
func snapCursorToGrapheme(ti *textinput.Model, before int) {
	value, pos := []rune(ti.Value()), ti.Position()
	if pos <= 0 || pos >= len(value) {
		return
	}
	lower, upper := graphemeEdges(value, pos)
	switch {
	case pos == lower:
	case pos < before:
		ti.SetCursor(lower)
	default:
		ti.SetCursor(upper)
	}
}

// graphemeEdges returns the rune indexes of the grapheme boundaries around
// pos: the greatest boundary at or before it and the least at or after it (both
// equal pos when pos is itself a boundary).
func graphemeEdges(value []rune, pos int) (lower, upper int) {
	lower, upper = 0, len(value)
	offset := 0
	graphemes := uniseg.NewGraphemes(string(value))
	for graphemes.Next() {
		if offset <= pos {
			lower = offset
		}
		if offset >= pos {
			upper = offset
			break
		}
		offset += len(graphemes.Runes())
	}
	if lower == pos {
		upper = pos
	}
	return lower, upper
}

// isClipboardPaste reports whether msg is the textinput's own paste key
// (KeyMap.Paste, Ctrl+V). bubbles answers it with a command that reads the
// system clipboard and a message only the textinput itself can unwrap, and
// every host used to drop that command, so the key silently did nothing (task
// uz2). ior also runs as root, often over SSH, where the system clipboard is
// usually unreachable, so reading it is not an option worth wiring up: the key
// is swallowed here, once for every input, and pasting is the terminal's own
// paste (bracketed paste arrives as tea.PasteMsg, which the textinput handles
// and which is not touched).
func isClipboardPaste(ti textinput.Model, msg tea.Msg) bool {
	press, ok := msg.(tea.KeyPressMsg)
	return ok && key.Matches(press, ti.KeyMap.Paste)
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
