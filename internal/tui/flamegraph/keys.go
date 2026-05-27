package flamegraph

import (
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

func keyString(msg tea.KeyPressMsg) string {
	if s := msg.String(); s != "" {
		return s
	}
	return msg.Text
}

func isSearchOpenKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "/" }
func isNextMatchKey(msg tea.KeyPressMsg) bool  { return keyString(msg) == "n" }
func isPrevMatchKey(msg tea.KeyPressMsg) bool  { return keyString(msg) == "N" }
func isPauseKey(msg tea.KeyPressMsg) bool {
	k := keyString(msg)
	return k == " " || k == "space" || msg.Code == tea.KeySpace
}
func isResetBaselineKey(msg tea.KeyPressMsg) bool {
	return keyString(msg) == "r"
}
func isCycleOrderKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "o" }
func isCycleMetricKey(msg tea.KeyPressMsg) bool {
	return keyString(msg) == "b"
}
func isToggleHeightKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "v" }
func isHelpToggleKey(msg tea.KeyPressMsg) bool   { return keyString(msg) == "?" }

func isZoomInKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomIn) || msg.Code == tea.KeyEnter || strings.EqualFold(keyString(msg), "enter")
}

func isZoomUndoKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomUndo) || msg.Code == tea.KeyBackspace || msg.Code == tea.KeyEsc
}

func isZoomResetKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomReset)
}

func isMoveShallowerKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.MoveShallower) || msg.Code == tea.KeyDown || keyMatchesDirection(k, "down", 'B')
}

func isMoveDeeperKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.MoveDeeper) || msg.Code == tea.KeyUp || keyMatchesDirection(k, "up", 'A')
}

func isPrevSiblingKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.PrevSibling) || msg.Code == tea.KeyLeft || keyMatchesDirection(k, "left", 'D')
}

func isNextSiblingKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.NextSibling) || msg.Code == tea.KeyRight || keyMatchesDirection(k, "right", 'C')
}

func isJumpTopKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := strings.ToLower(keyString(msg))
	return key.Matches(msg, keys.JumpTop) || msg.Code == tea.KeyPgUp || k == "pgup" || k == "pageup"
}

func isJumpRootKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := strings.ToLower(keyString(msg))
	return key.Matches(msg, keys.JumpRoot) || msg.Code == tea.KeyPgDown || k == "pgdown" || k == "pgdn" || k == "pagedown"
}

func keyMatchesDirection(keyName, plain string, ansiFinal byte) bool {
	if keyName == plain || strings.HasSuffix(keyName, "+"+plain) {
		return true
	}
	return isArrowEscapeSequence(keyName, ansiFinal)
}

func isArrowEscapeSequence(value string, ansiFinal byte) bool {
	body, ok := strings.CutPrefix(value, "\x1b")
	if !ok || len(body) < 2 {
		return false
	}
	switch body[0] {
	case '[':
		return body[len(body)-1] == ansiFinal
	case 'O':
		return len(body) == 2 && body[1] == ansiFinal
	default:
		return false
	}
}
