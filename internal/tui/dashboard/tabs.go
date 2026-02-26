package dashboard

import (
	"fmt"
	common "ior/internal/tui/common"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

// Tab is a dashboard tab identifier.
type Tab int

const (
	// TabOverview is the high-level summary tab.
	TabOverview Tab = iota
	// TabSyscalls is the syscall table tab.
	TabSyscalls
	// TabFiles is the file ranking tab.
	TabFiles
	// TabProcesses is the process breakdown tab.
	TabProcesses
	// TabLatency is the latency histogram tab.
	TabLatency
	// TabStream is the live event stream tab.
	TabStream
)

var allTabs = []Tab{
	TabOverview,
	TabSyscalls,
	TabFiles,
	TabProcesses,
	TabLatency,
	TabStream,
}

func (t Tab) String() string {
	switch t {
	case TabOverview:
		return "Overview"
	case TabSyscalls:
		return "Syscalls"
	case TabFiles:
		return "Files"
	case TabProcesses:
		return "Processes"
	case TabLatency:
		return "Latency+Gaps"
	case TabStream:
		return "Stream"
	default:
		return "Unknown"
	}
}

func nextTab(tab Tab) Tab {
	idx := tabIndex(tab)
	return allTabs[(idx+1)%len(allTabs)]
}

func prevTab(tab Tab) Tab {
	idx := tabIndex(tab)
	if idx == 0 {
		return allTabs[len(allTabs)-1]
	}
	return allTabs[idx-1]
}

func tabIndex(tab Tab) int {
	for i, candidate := range allTabs {
		if candidate == tab {
			return i
		}
	}
	return 0
}

func renderTabBar(active Tab, width int) string {
	if width > 0 && width < 90 {
		return renderTabBarPlain(active, width)
	}
	build := func(short bool) string {
		parts := make([]string, 0, len(allTabs))
		for i, tab := range allTabs {
			label := fmt.Sprintf("%d:%s", i+1, tabLabel(tab, short))
			if tab == active {
				parts = append(parts, common.TabActiveStyle.Render(label))
			} else {
				parts = append(parts, common.TabInactiveStyle.Render(label))
			}
		}
		return lipgloss.JoinHorizontal(lipgloss.Left, parts...)
	}

	bar := build(false)
	if width > 0 && lipgloss.Width(bar) > width {
		bar = build(true)
	}
	if width > 0 && lipgloss.Width(bar) > width {
		label := fmt.Sprintf("%d:%s", tabIndex(active)+1, tabLabel(active, false))
		bar = common.TabActiveStyle.Render(label)
	}
	if width <= 0 {
		return bar
	}
	styled := lipgloss.NewStyle().Width(width).Render(bar)
	if strings.Contains(styled, "\n") {
		return renderTabBarPlain(active, width)
	}
	return styled
}

func renderHelpBar(keys common.KeyMap, width int) string {
	sections := keys.DashboardStatusHelpSections()
	lines := make([]string, 0, len(sections))
	for _, section := range sections {
		parts := make([]string, 0, len(section.Bindings))
		for _, binding := range section.Bindings {
			help := binding.Help()
			parts = append(parts, help.Key+" "+help.Desc)
		}
		line := section.Title + ": " + strings.Join(parts, " • ")
		if width > 0 {
			line = truncatePlain(line, width)
		}
		lines = append(lines, line)
	}
	text := strings.Join(lines, "\n")
	if width > 0 && width < 90 {
		return text
	}
	return common.HelpBarStyle.Width(width).Render(text)
}

func renderHelpHint(width int) string {
	hint := "press H for help"
	if width > 0 && width < 90 {
		return hint
	}
	return common.HelpBarStyle.Width(width).Render(hint)
}

func wrapHelpLines(parts []string, width int) (string, string) {
	if len(parts) == 0 {
		return "", ""
	}
	if width <= 0 {
		return strings.Join(parts, " • "), ""
	}
	max := width
	lines := []string{"", ""}
	line := 0
	for _, part := range parts {
		token := part
		if lines[line] != "" {
			token = " • " + part
		}
		if utf8.RuneCountInString(lines[line]+token) <= max {
			lines[line] += token
			continue
		}
		if line == 0 {
			line = 1
			if utf8.RuneCountInString(part) <= max {
				lines[line] = part
			}
			continue
		}
		break
	}
	lines[0] = truncatePlain(lines[0], max)
	lines[1] = truncatePlain(lines[1], max)
	return lines[0], lines[1]
}

func tabLabel(tab Tab, short bool) string {
	if !short {
		return tab.String()
	}
	switch tab {
	case TabOverview:
		return "Ovr"
	case TabSyscalls:
		return "Sys"
	case TabFiles:
		return "Fil"
	case TabProcesses:
		return "Pro"
	case TabLatency:
		return "Lat"
	case TabStream:
		return "Str"
	default:
		return "Unk"
	}
}

func truncatePlain(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	r := []rune(s)
	return string(r[:width-1]) + "…"
}

func renderTabBarPlain(active Tab, width int) string {
	parts := make([]string, 0, len(allTabs))
	for i, tab := range allTabs {
		label := fmt.Sprintf("%d:%s", i+1, tabLabel(tab, true))
		if tab == active {
			label = "[" + label + "]"
		}
		parts = append(parts, label)
	}
	text := strings.Join(parts, " ")
	if width > 0 {
		text = truncatePlain(text, width)
		padding := width - utf8.RuneCountInString(text)
		if padding > 0 {
			text += strings.Repeat(" ", padding)
		}
	}
	return text
}
