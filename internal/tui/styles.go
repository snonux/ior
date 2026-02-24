package tui

import common "ior/internal/tui/common"

var (
	// Palette colors shared across the TUI package.
	ColorBackground = common.ColorBackground
	ColorPanel      = common.ColorPanel
	ColorPrimary    = common.ColorPrimary
	ColorAccent     = common.ColorAccent
	ColorMuted      = common.ColorMuted
	ColorText       = common.ColorText
	ColorDanger     = common.ColorDanger
)

var (
	// ScreenStyle is the base style for full-screen models.
	ScreenStyle = common.ScreenStyle

	// HeaderStyle is used by top-level titles and screen headers.
	HeaderStyle = common.HeaderStyle

	// TabActiveStyle is applied to the currently-selected tab.
	TabActiveStyle = common.TabActiveStyle

	// TabInactiveStyle is applied to non-selected tabs.
	TabInactiveStyle = common.TabInactiveStyle

	// PanelStyle is used for boxed sections.
	PanelStyle = common.PanelStyle

	// HelpBarStyle is used for keybinding hints at the bottom.
	HelpBarStyle = common.HelpBarStyle

	// HighlightStyle emphasizes inline values.
	HighlightStyle = common.HighlightStyle

	// ErrorStyle is used for fatal or warning messages.
	ErrorStyle = common.ErrorStyle
)
