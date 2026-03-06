package common

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Palette defines themed colors shared across the TUI package.
type Palette struct {
	Background color.Color
	Panel      color.Color
	Primary    color.Color
	Accent     color.Color
	Muted      color.Color
	Text       color.Color
	Danger     color.Color
}

// NewPalette returns a color palette for dark or light terminal backgrounds.
func NewPalette(isDark bool) Palette {
	if isDark {
		return Palette{
			Background: lipgloss.Color("235"),
			Panel:      lipgloss.Color("238"),
			Primary:    lipgloss.Color("75"),
			Accent:     lipgloss.Color("222"),
			Muted:      lipgloss.Color("246"),
			Text:       lipgloss.Color("255"),
			Danger:     lipgloss.Color("203"),
		}
	}

	return Palette{
		Background: lipgloss.Color("255"),
		Panel:      lipgloss.Color("250"),
		Primary:    lipgloss.Color("26"),
		Accent:     lipgloss.Color("88"),
		Muted:      lipgloss.Color("242"),
		Text:       lipgloss.Color("235"),
		Danger:     lipgloss.Color("160"),
	}
}

var (
	// Palette colors shared across the TUI package.
	ColorBackground color.Color
	ColorPanel      color.Color
	ColorPrimary    color.Color
	ColorAccent     color.Color
	ColorMuted      color.Color
	ColorText       color.Color
	ColorDanger     color.Color
)

var (
	// ScreenStyle is the base style for full-screen models.
	ScreenStyle lipgloss.Style

	// HeaderStyle is used by top-level titles and screen headers.
	HeaderStyle lipgloss.Style

	// TabActiveStyle is applied to the currently-selected tab.
	TabActiveStyle lipgloss.Style

	// TabInactiveStyle is applied to non-selected tabs.
	TabInactiveStyle lipgloss.Style

	// PanelStyle is used for boxed sections.
	PanelStyle lipgloss.Style

	// HelpBarStyle is used for keybinding hints at the bottom.
	HelpBarStyle lipgloss.Style

	// HighlightStyle emphasizes inline values.
	HighlightStyle lipgloss.Style

	// ErrorStyle is used for fatal or warning messages.
	ErrorStyle lipgloss.Style
)

// ApplyPalette updates shared colors and styles to match the provided theme.
func ApplyPalette(isDark bool) {
	palette := NewPalette(isDark)
	ColorBackground = palette.Background
	ColorPanel = palette.Panel
	ColorPrimary = palette.Primary
	ColorAccent = palette.Accent
	ColorMuted = palette.Muted
	ColorText = palette.Text
	ColorDanger = palette.Danger

	ScreenStyle = lipgloss.NewStyle().Foreground(ColorText)
	HeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)
	TabActiveStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorBackground).
		Background(ColorPrimary).
		Padding(0, 1)
	TabInactiveStyle = lipgloss.NewStyle().
		Foreground(ColorMuted).
		Padding(0, 1)
	PanelStyle = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorPanel).
		Padding(0, 1)
	HelpBarStyle = lipgloss.NewStyle().
		Foreground(ColorMuted).
		BorderTop(true).
		BorderForeground(ColorPanel)
	HighlightStyle = lipgloss.NewStyle().Bold(true).Foreground(ColorAccent)
	ErrorStyle = lipgloss.NewStyle().Bold(true).Foreground(ColorDanger)
}

func init() {
	ApplyPalette(true)
}
