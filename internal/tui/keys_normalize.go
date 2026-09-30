package tui

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
)

// maxTrackedPressedKeys bounds the pressed-key set. A release can be lost (the
// window loses focus, the terminal drops it), leaving a stale entry; a real
// keyboard cannot hold anywhere near this many keys at once, so overflowing
// means the set is stale and is simply reset.
const maxTrackedPressedKeys = 64

// normalizeKeyEvent turns the raw key stream into one KeyPressMsg per physical
// keystroke. The view requests kitty "report event types", so on kitty-protocol
// terminals every key produces a press and, later, a release. The release of
// key A can arrive after the press of key B when typing fast (a, b, ^a, ^b), so
// pairing a release with "the single previous event" is wrong: it replayed the
// release as a new press and turned "ab" into "abab". Instead every press adds
// its key to a set of currently held keys and a release of a held key is just
// the end of that keystroke and is dropped, however long the key was held and
// whatever else was typed meanwhile.
func (m *Model) normalizeKeyEvent(msg tea.Msg) (tea.Msg, bool) {
	switch keyMsg := msg.(type) {
	case tea.KeyPressMsg:
		if m.shouldSuppressPress(keyEventID(keyMsg)) {
			return nil, false
		}
		m.markKeyPressed(keyMsg)
		return keyMsg, true
	case tea.KeyReleaseMsg:
		return m.normalizeKeyRelease(tea.KeyPressMsg(keyMsg))
	case tea.BlurMsg:
		// Releases that happen while another window has focus never reach us,
		// so forget what we believed was held.
		m.kb.pressed = nil
		return msg, true
	default:
		return msg, true
	}
}

// normalizeKeyRelease decides what a release event means: the end of a press we
// already delivered (drop it), a stray release on a terminal that does report
// presses (drop it), or, on a terminal that reports only releases, the only
// signal that the key was struck (deliver it as a press).
func (m *Model) normalizeKeyRelease(pressMsg tea.KeyPressMsg) (tea.Msg, bool) {
	if m.markKeyReleased(pressMsg) {
		return nil, false
	}
	if m.terminalReportsEventTypes() {
		// The terminal confirmed it reports press/release/repeat events, so a
		// key struck for real always produced a press first and a release with
		// no tracked press is not a keystroke. Typical causes: the Enter that
		// launched the program (its press went to the shell), or a key held
		// across a BlurMsg, which clears the held set. Replaying such a release
		// as a press would fire a phantom keystroke (e.g. a spurious Enter on
		// the first screen). Trade-off: if such a terminal ever lost a press
		// but kept the release, that keystroke is lost instead of duplicated;
		// that is far rarer than the phantom-key cases above.
		return nil, false
	}
	if !releaseHasIdentity(pressMsg) {
		// Ignore release messages that don't carry enough identity information.
		// Some terminals emit these before a usable press event.
		return nil, false
	}
	// Fallback for terminals that do not (or not yet) report event types: no
	// press was seen for this key, so treat the release as the keystroke for
	// terminals that only emit release events.
	if shouldSuppressMatchingPressAfterRelease(pressMsg) {
		m.armPressSuppression(keyEventID(pressMsg))
	}
	return pressMsg, true
}

// terminalReportsEventTypes is true once the terminal has answered the
// keyboard-enhancements query with the kitty "report event types" flag set.
// Until that answer arrives (or on terminals that never answer) it is false and
// the release-as-press fallback stays active.
func (m *Model) terminalReportsEventTypes() bool {
	return m.kb.enhancementsKnown && m.kb.enhancements.SupportsEventTypes()
}

// physicalKey identifies the key independent of modifier and text state. A
// release can differ from its press in the modifiers (shift can be let go
// before the letter), and for shifted symbols and non-ASCII or composed text it
// even reports a different Code (press '!' Code '!', release of Shift+1 Code
// '1'). Only for ASCII letters, digits and named keys (Enter, Space, arrows,
// ...) do the press and release Codes match, so pairing is by Code alone and is
// reliable only for those keys.
//
// Known limitation: a press whose release reports a different Code leaves a
// stale entry in the held set. It is harmless: on a terminal that reports event
// types every release is dropped anyway (paired or not), so the stale entry
// changes nothing; it can only mis-drop a later release-only keystroke with
// that same Code, which needs presses to have been seen, i.e. not a
// release-only terminal. The set is cleared on blur and capped at
// maxTrackedPressedKeys, so stale entries never accumulate.
func physicalKey(msg tea.KeyPressMsg) rune {
	return msg.Code
}

// markKeyPressed records that the key is held. Auto-repeat presses re-add the
// same key, which is harmless.
func (m *Model) markKeyPressed(msg tea.KeyPressMsg) {
	if m.kb.pressed == nil || len(m.kb.pressed) >= maxTrackedPressedKeys {
		m.kb.pressed = make(map[rune]struct{})
	}
	m.kb.pressed[physicalKey(msg)] = struct{}{}
}

// markKeyReleased removes the key from the held set and reports whether it was
// in it, i.e. whether this release only ends a press that was already handled.
func (m *Model) markKeyReleased(msg tea.KeyPressMsg) bool {
	key := physicalKey(msg)
	if _, held := m.kb.pressed[key]; !held {
		return false
	}
	delete(m.kb.pressed, key)
	return true
}

func (m *Model) shouldSuppressPress(keyID string) bool {
	if m.kb.suppressID == "" {
		return false
	}
	if time.Now().After(m.kb.suppressUntil) {
		m.clearPressSuppression()
		return false
	}
	if keyID == "" || keyID != m.kb.suppressID {
		return false
	}
	m.clearPressSuppression()
	return true
}

func (m *Model) armPressSuppression(keyID string) {
	if keyID == "" {
		return
	}
	// Keep this short so fast repeated key presses still work naturally.
	m.kb.suppressID = keyID
	m.kb.suppressUntil = time.Now().Add(60 * time.Millisecond)
}

func (m *Model) clearPressSuppression() {
	m.kb.suppressID = ""
	m.kb.suppressUntil = time.Time{}
}

func keyEventID(msg tea.KeyPressMsg) string {
	return fmt.Sprintf("code:%d/mod:%d/key:%q/text:%q", msg.Code, msg.Mod, msg.String(), msg.Text)
}

func releaseHasIdentity(msg tea.KeyPressMsg) bool {
	if msg.Text != "" {
		return true
	}
	keyStr := msg.String()
	if keyStr != "" && keyStr != "\x00" {
		return true
	}
	// Some terminals emit release-only space events without text identity.
	return msg.Code == tea.KeySpace
}

func shouldSuppressMatchingPressAfterRelease(msg tea.KeyPressMsg) bool {
	keyStr := msg.String()
	return msg.Code == tea.KeySpace || keyStr == " " || keyStr == "space" || msg.Text == " "
}
