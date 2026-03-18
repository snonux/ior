package tui

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
)

func (m *Model) normalizeKeyEvent(msg tea.Msg) (tea.Msg, bool) {
	switch keyMsg := msg.(type) {
	case tea.KeyPressMsg:
		keyID := keyEventID(keyMsg)
		if m.shouldSuppressPress(keyID) {
			return nil, false
		}
		m.recordKeyEvent(keyMsg, true)
		return keyMsg, true
	case tea.KeyReleaseMsg:
		pressMsg := tea.KeyPressMsg(keyMsg)
		keyID := keyEventID(pressMsg)
		if m.kb.lastEventWasPress && keyID != "" && keyID == m.kb.lastEventID && time.Since(m.kb.lastEventAt) <= 500*time.Millisecond {
			// Some terminals emit both press+release; avoid handling release as a duplicate.
			m.kb.lastEventWasPress = false
			return nil, false
		}
		if !releaseHasIdentity(pressMsg) {
			// Ignore release messages that don't carry enough identity information.
			// Some terminals emit these before a usable press event.
			return nil, false
		}
		// Fallback: treat release as press for terminals that only emit release events.
		if shouldSuppressMatchingPressAfterRelease(pressMsg) {
			m.armPressSuppression(keyID)
		}
		m.recordKeyEvent(pressMsg, false)
		return pressMsg, true
	default:
		return msg, true
	}
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

func (m *Model) recordKeyEvent(msg tea.KeyPressMsg, wasPress bool) {
	m.kb.lastEventID = keyEventID(msg)
	m.kb.lastEventAt = time.Now()
	m.kb.lastEventWasPress = wasPress
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
