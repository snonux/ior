package tui

import common "ior/internal/tui/common"

// KeyMap groups all key bindings shared by TUI screens.
type KeyMap = common.KeyMap

// Keys contains the default shared key map.
var Keys = common.Keys

// DefaultKeyMap builds the default key bindings used by models.
func DefaultKeyMap() KeyMap {
	return common.DefaultKeyMap()
}
