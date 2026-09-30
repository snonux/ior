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
// already delivered (drop it) or, for terminals that report only releases, the
// only signal that the key was struck (deliver it as a press).
func (m *Model) normalizeKeyRelease(pressMsg tea.KeyPressMsg) (tea.Msg, bool) {
	if m.markKeyReleased(pressMsg) {
		return nil, false
	}
	if !releaseHasIdentity(pressMsg) {
		// Ignore release messages that don't carry enough identity information.
		// Some terminals emit these before a usable press event.
		return nil, false
	}
	// Fallback: no press was seen for this key, so treat the release as the
	// keystroke for terminals that only emit release events.
	if shouldSuppressMatchingPressAfterRelease(pressMsg) {
		m.armPressSuppression(keyEventID(pressMsg))
	}
	return pressMsg, true
}

// physicalKey identifies the key independent of modifier and text state. A
// release carries neither the text nor necessarily the modifiers of its press
// (shift can be let go before the letter), so only the base key code pairs
// the two reliably.
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
