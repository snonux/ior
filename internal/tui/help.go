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

	box := common.PanelStyle.Copy().
		Width(boxWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

type helpSection struct {
	title string
	lines []string
}

func (m Model) helpSections() []helpSection {
	globalLines := []string{
		"H help  esc/? close help  q quit",
		"f filter  p pid picker  t tid picker  o probes  R parquet rec",
	}
	if help := m.keys.Export.Help(); help.Key != "" || help.Desc != "" {
		globalLines[1] += "  e stream export"
	}

	return []helpSection{
		{
			title: "Global",
			lines: globalLines,
		},
		{
			title: "Dashboard Tabs",
			lines: []string{
				"tab/shift+tab tabs  1..7 jump tab  r reset baseline  I auto-reset  R parquet rec",
				"sys/files/proc/stream tables: arrows or hjkl move  pgup/pgdown page  g/G top/bottom",
				"sys/files/proc tables: s sort  S reverse sort",
				"sys/proc: v bubbles  b metric events/bytes",
				"files: d dirs toggle  v bubbles (dirs only)  b metric",
				"flame: arrows/hjkl nav  enter/click zoom  click ancestor undo  u/bs/esc undo  o order",
				"flame: / filter  n/N match next/prev  space pause  b metric",
				"stream: space pause  enter push filter  esc/F undo  /? n/N search",
				"stream: x/X export  E open",
			},
		},
		{
			title: "PID/TID Picker",
			lines: []string{
				"enter select  r refresh  esc/q back",
			},
		},
	}
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

	box := common.PanelStyle.Copy().Width(boxWidth).Render(strings.Join(lines, "\n"))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func truncateHelpLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	r := []rune(s)
	if len(r) >= width {
		return string(r[:width-1]) + "…"
	}
	return s
}
