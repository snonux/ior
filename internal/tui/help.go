package tui

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"
)

func renderHelpOverlay(width, height int, groups [][]key.Binding) string {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}

	lines := []string{"Help"}
	for _, group := range groups {
		parts := make([]string, 0, len(group))
		for _, binding := range group {
			h := binding.Help()
			parts = append(parts, fmt.Sprintf("%s %s", h.Key, h.Desc))
		}
		lines = append(lines, strings.Join(parts, " • "))
	}
	lines = append(lines, "", "Esc/?/q close")

	boxWidth := width - 6
	if boxWidth < 72 {
		boxWidth = 72
	}

	box := common.Current().PanelStyle.
		Width(boxWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

type helpSection struct {
	title string
	lines []string
}

func (m *Model) helpSections() []helpSection {
	// The Global section is capped at three lines: at 80x24 the overlay keeps
	// only height-4 = 20 lines, and a fourth Global line pushed the last
	// Dashboard Tabs line (the "stream: x/X export  E open" hint) out of
	// view. Every line must also stay within 70 cells, the help box content
	// width at 80 columns, or it is cut with an ellipsis.
	//
	// The export key rides on the first line. "R parquet rec" is not repeated
	// here: the Dashboard Tabs section already lists it. Attaching a whole
	// family at runtime is the probes modal's Families view (tab), which its
	// own not-traced hint spells out, so the note only has to say which key
	// opens the modal: O works on every tab, o is shadowed by the Flame tab's
	// frame-order key.
	line0 := "H help  esc/? close help  q quit"
	if m.keys.ExportEnabled() {
		line0 += "  e stream export"
	}
	globalLines := []string{
		line0,
		"f filter  p pid picker  t tid picker  o/O probes  [ ] scope family",
		"O opens probes on every tab (on Flame, o cycles the frame order)",
	}

	return []helpSection{
		{
			title: "Global",
			lines: globalLines,
		},
		{
			title: "Dashboard Tabs",
			lines: dashboardTabHelpLines(m.keys.ExportEnabled()),
		},
		{
			title: "PID/TID Picker",
			lines: []string{
				"enter select  esc back  ctrl+r refresh  (typing filters the list)",
				"with the filter unfocused (up/down): r refresh  q back  H help",
			},
		},
	}
}

// dashboardTabHelpLines builds the Dashboard Tabs section of the global help
// overlay. The stream export shortcuts (x/X/E) line is included only when
// export is enabled, so -tuiExport=false hides both the hints and the
// shortcuts themselves. The last line explains the status line's warning
// badge.
func dashboardTabHelpLines(exportEnabled bool) []string {
	lines := []string{
		"tab/shift+tab tabs  1..7 jump tab  r reset baseline  R parquet rec",
		"F1 toggle the dashboard help bar (H opens this overlay)",
		"I cycle auto-reset (off → 10s → 30s → 1m → 2m → 5m); status shows remaining/total",
		"sys/files/proc/stream tables: arrows or hjkl move  pgup/pgdown page  g/G top/bottom",
		"sys/files/proc tables: s sort  S reverse sort",
		"sys/proc: v bubbles  b metric events/bytes",
		"files: d dirs toggle  v bubbles (dirs only)  b metric",
		"flame: arrows/hjkl nav  enter/click zoom  click ancestor undo  u/bs/esc undo  o order",
		"flame: / filter  n/N match next/prev  space pause  b metric",
		// "enter filter/warning": a filter from the selected cell, or, on
		// a warning row, its whole message. Spelled out it is over the 70
		// cells an 80-column overlay shows (see helpSections); the paused
		// footer says which of the two the selected row gets.
		"stream: space pause  enter filter/warning  esc/F undo  /? n/N search",
	}
	if exportEnabled {
		lines = append(lines, "stream: x/X export  E open")
	}
	// The status-line warning badge is drawn only off the Stream tab, so the
	// overlay says what it points at (task ys2). It goes last: an 80x24
	// overlay cuts the section from the bottom, and the key hints above it
	// outrank an explanation of a badge the user can follow without it.
	return append(lines, `status "warnings: N (7:Stream)": warning rows on the Stream tab`)
}

func renderGlobalHelpOverlay(width, height int, sections []helpSection) string {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}

	boxWidth := width - 4
	if boxWidth > 100 {
		boxWidth = 100
	}
	if boxWidth < 74 {
		boxWidth = 74
	}
	contentWidth := boxWidth - 4
	if contentWidth < 20 {
		contentWidth = boxWidth
	}

	lines := make([]string, 0, 24)
	lines = append(lines, "Help")
	for _, section := range sections {
		lines = append(lines, "")
		lines = append(lines, section.title)
		for _, line := range section.lines {
			lines = append(lines, "  "+truncateHelpLine(line, contentWidth-2))
		}
	}
	lines = append(lines, "", "Esc/q close")

	maxLines := height - 4
	if maxLines < 6 {
		maxLines = 6
	}
	if len(lines) > maxLines {
		lines = lines[:maxLines-1]
		lines = append(lines, truncateHelpLine("... (resize for full help)", contentWidth))
	}

	box := common.Current().PanelStyle.Width(boxWidth).Render(strings.Join(lines, "\n"))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// truncateHelpLine shortens s to at most width display cells, ending in "…"
// when cut. Measuring and cutting by display width (common.TruncateRight)
// keeps wide runes from overflowing the help box.
func truncateHelpLine(s string, width int) string {
	return common.TruncateRight(s, width, common.Ellipsis)
}
