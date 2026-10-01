package eventstream

import (
	"strings"
	"unicode/utf8"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// namedKeyCodes maps the key names Bubble Tea's Key.Keystroke prints for the
// named (non-printable) keys back to their key codes, plus the aliases the
// stream's own key handling uses ("pgdn", "pagedown", "pageup"). It is built
// from the codes' own Keystroke names, so it stays in step with Bubble Tea's
// spelling ("pgdown", "esc", "delete", ...).
var namedKeyCodes = buildNamedKeyCodes()

// keyNameModifiers maps a modifier prefix of a key name ("ctrl+" in
// "ctrl+a") to its modifier.
var keyNameModifiers = map[string]tea.KeyMod{
	"ctrl":  tea.ModCtrl,
	"alt":   tea.ModAlt,
	"shift": tea.ModShift,
	"meta":  tea.ModMeta,
	"hyper": tea.ModHyper,
	"super": tea.ModSuper,
}

func buildNamedKeyCodes() map[string]rune {
	codes := []rune{
		tea.KeyUp, tea.KeyDown, tea.KeyLeft, tea.KeyRight,
		tea.KeyHome, tea.KeyEnd, tea.KeyPgUp, tea.KeyPgDown,
		tea.KeyBackspace, tea.KeyDelete, tea.KeyInsert,
		tea.KeyTab, tea.KeyEnter, tea.KeyEsc, tea.KeySpace,
	}
	names := make(map[string]rune, len(codes)+3)
	for _, code := range codes {
		names[tea.Key{Code: code}.Keystroke()] = code
	}
	names["pgdn"] = tea.KeyPgDown
	names["pagedown"] = tea.KeyPgDown
	names["pageup"] = tea.KeyPgUp
	return names
}

// keyMsgFromString turns one key name, as tea.KeyPressMsg.String spells it
// ("a", "space", "home", "ctrl+a", "alt+left"), back into the key press it
// names, and reports whether it is one. HandleKey takes such names; the
// stream modals hand the result to their bubbles textinput, which acts on
// the key (Code and Mod) and types only the press's Text.
//
// A single rune without modifiers is typed text (Text set). A named key or a
// rune with modifiers is a key without text: "ctrl+x" is Ctrl+X, which the
// textinput ignores, and never the five runes "ctrl+x" (task 9z2; the old
// mapping knew only esc, enter, tab, up, down and space and typed every other
// name into the search and export inputs). Anything else (an unknown name
// such as "f13", a modifier on an unknown name, or a multi-rune string, which
// is not a single key's name) is not a key, and the caller ignores it.
// Composed multi-rune text reaches the modals as the original key press
// through HandleTeaKey, or through HandlePaste.
func keyMsgFromString(keyStr string) (tea.KeyPressMsg, bool) {
	if code, ok := namedKeyCodes[keyStr]; ok {
		return namedKeyPress(code, 0), true
	}
	if utf8.RuneCountInString(keyStr) == 1 {
		r, _ := utf8.DecodeRuneInString(keyStr)
		return tea.KeyPressMsg{Code: r, Text: keyStr}, true
	}
	return modifiedKeyMsg(keyStr)
}

// modifiedKeyMsg parses a key name with modifier prefixes ("ctrl+alt+b"):
// every "+"-separated part before the last must be a modifier and the last
// part a named key or a single rune. A modified key carries no Text.
func modifiedKeyMsg(keyStr string) (tea.KeyPressMsg, bool) {
	parts := strings.Split(keyStr, "+")
	if len(parts) < 2 {
		return tea.KeyPressMsg{}, false
	}
	var mod tea.KeyMod
	for _, part := range parts[:len(parts)-1] {
		m, ok := keyNameModifiers[part]
		if !ok {
			return tea.KeyPressMsg{}, false
		}
		mod |= m
	}
	base := parts[len(parts)-1]
	if code, ok := namedKeyCodes[base]; ok {
		return namedKeyPress(code, mod), true
	}
	if utf8.RuneCountInString(base) == 1 {
		r, _ := utf8.DecodeRuneInString(base)
		return tea.KeyPressMsg{Code: r, Mod: mod}, true
	}
	return tea.KeyPressMsg{}, false
}

// namedKeyPress is the press of a named key with mod. Space is the one named
// key that types text, as Bubble Tea's own space press does.
func namedKeyPress(code rune, mod tea.KeyMod) tea.KeyPressMsg {
	msg := tea.KeyPressMsg{Code: code, Mod: mod}
	if code == tea.KeySpace && mod == 0 {
		msg.Text = " "
	}
	return msg
}

// guardDeleteWordForward returns msg for ti, except that a delete-word-forward
// press (Alt+D, Alt+Delete) with the cursor on the value's last rune becomes
// a plain Delete, which removes the same rune. bubbles v2.0.0's
// textinput.deleteWordForward indexes one past the value there and panics
// (task kz2 fixes this for every textinput); the stream modals receive the
// real key press since task 9z2 instead of the literal text "alt+d", so they
// guard it here rather than gain a new way to crash.
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
