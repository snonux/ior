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
	// The export key rides on the first line: appended to line1 it made the
	// line 80 cells and the 70-cell help box (80 columns) cut it to "e st...".
	line0 := "H help  esc/? close help  q quit"
	if m.keys.ExportEnabled() {
		line0 += "  e stream export"
	}
	line1 := "f filter  p pid picker  t tid picker  o/O probes  R parquet rec"
	// '['/']' only re-scope the view; attaching a whole family at runtime is
	// the probes modal's Families view (o/O, then tab), hence the last line.
	// O works on every tab; o is shadowed by the Flame tab's frame-order key.
	// The note has its own line: the help box is 70 cells wide at 80 columns
	// and a longer combined line was cut mid-note.
	globalLines := []string{
		line0,
		line1,
		"[ ] scope view to a family  o/O tab: attach/detach families",
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
				"enter select  r refresh  esc/q back",
			},
		},
	}
}

// dashboardTabHelpLines builds the Dashboard Tabs section of the global help
// overlay. The stream export shortcuts (x/X/E) line is included only when
// export is enabled, so -tuiExport=false hides both the hints and the
// shortcuts themselves.
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
		"stream: space pause  enter push filter  esc/F undo  /? n/N search",
	}
	if exportEnabled {
		lines = append(lines, "stream: x/X export  E open")
	}
	return lines
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
