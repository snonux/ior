package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Palette colors shared across the TUI package.
	ColorBackground = lipgloss.Color("235")
	ColorPanel      = lipgloss.Color("238")
	ColorPrimary    = lipgloss.Color("75")
	ColorAccent     = lipgloss.Color("222")
	ColorMuted      = lipgloss.Color("246")
	ColorText       = lipgloss.Color("255")
	ColorDanger     = lipgloss.Color("203")
)

var (
	// ScreenStyle is the base style for full-screen models.
	ScreenStyle = lipgloss.NewStyle().
			Foreground(ColorText).
			Background(ColorBackground)

	// HeaderStyle is used by top-level titles and screen headers.
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary)

	// TabActiveStyle is applied to the currently-selected tab.
	TabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorBackground).
			Background(ColorPrimary).
			Padding(0, 1)

	// TabInactiveStyle is applied to non-selected tabs.
	TabInactiveStyle = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Background(ColorPanel).
				Padding(0, 1)

	// PanelStyle is used for boxed sections.
	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorPanel).
			Padding(0, 1)

	// HelpBarStyle is used for keybinding hints at the bottom.
	HelpBarStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			BorderTop(true).
			BorderForeground(ColorPanel)

	// HighlightStyle emphasizes inline values.
	HighlightStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorAccent)

	// ErrorStyle is used for fatal or warning messages.
	ErrorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorDanger)
)
