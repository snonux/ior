package common

import (
	"image/color"
	"sync/atomic"

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

// Theme is an immutable snapshot of the palette colors and every style derived
// from them. Theme values are never mutated after construction: ApplyPalette
// publishes a new snapshot atomically and renderers read it through Current,
// which makes theme switching safe while a Bubble Tea renderer goroutine is
// rendering.
type Theme struct {
	// Palette colors for the active theme.
	Palette

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

	// TableHeaderStyle is used by shared table headers.
	TableHeaderStyle lipgloss.Style

	// TableSelectedRowStyle highlights the selected row in shared tables.
	TableSelectedRowStyle lipgloss.Style

	// TableSelectedCellStyle highlights the selected cell in shared tables.
	TableSelectedCellStyle lipgloss.Style
}

// newTheme builds an immutable theme snapshot for the given terminal mode.
func newTheme(isDark bool) *Theme {
	palette := NewPalette(isDark)
	return &Theme{
		Palette: palette,

		ScreenStyle: lipgloss.NewStyle().Foreground(palette.Text),
		HeaderStyle: lipgloss.NewStyle().Bold(true).Foreground(palette.Primary),
		TabActiveStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(palette.Background).
			Background(palette.Primary).
			Padding(0, 1),
		TabInactiveStyle: lipgloss.NewStyle().
			Foreground(palette.Muted).
			Padding(0, 1),
		PanelStyle: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(palette.Panel).
			Padding(0, 1),
		HelpBarStyle: lipgloss.NewStyle().
			Foreground(palette.Muted).
			BorderTop(true).
			BorderForeground(palette.Panel),
		HighlightStyle: lipgloss.NewStyle().Bold(true).Foreground(palette.Accent),
		ErrorStyle:     lipgloss.NewStyle().Bold(true).Foreground(palette.Danger),
		TableHeaderStyle: lipgloss.NewStyle().
			Foreground(palette.Muted).
			BorderTop(true).
			BorderForeground(palette.Panel),
		TableSelectedRowStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(palette.Background).
			Background(palette.Primary),
		TableSelectedCellStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(palette.Background).
			Background(palette.Accent),
	}
}

// currentTheme holds the active immutable Theme snapshot. It is written only
// by ApplyPalette and read by Current, both safe for concurrent use.
var currentTheme atomic.Pointer[Theme]

// Current returns the active theme snapshot. The returned value is immutable
// and safe to use from any goroutine, including renderer goroutines. It never
// returns nil: the default dark palette is published during package
// initialization, before any goroutines start.
func Current() *Theme {
	return currentTheme.Load()
}

// ApplyPalette atomically publishes a new theme snapshot matching the provided
// terminal mode. It is safe to call while other goroutines render.
func ApplyPalette(isDark bool) {
	currentTheme.Store(newTheme(isDark))
}

func init() {
	ApplyPalette(true)
}
