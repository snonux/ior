package dashboard

import (
	"ior/internal/tui"
	"strings"

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
	// TabGaps is the inter-syscall gap tab.
	TabGaps
)

var allTabs = []Tab{
	TabOverview,
	TabSyscalls,
	TabFiles,
	TabProcesses,
	TabLatency,
	TabGaps,
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
		return "Latency"
	case TabGaps:
		return "Gaps"
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
	parts := make([]string, 0, len(allTabs))
	for _, tab := range allTabs {
		label := tab.String()
		if tab == active {
			parts = append(parts, tui.TabActiveStyle.Render(label))
		} else {
			parts = append(parts, tui.TabInactiveStyle.Render(label))
		}
	}

	bar := lipgloss.JoinHorizontal(lipgloss.Left, parts...)
	if width <= 0 {
		return bar
	}
	return lipgloss.NewStyle().Width(width).Render(bar)
}

func renderHelpBar(keys tui.KeyMap) string {
	parts := make([]string, 0, len(keys.DashboardShortHelp()))
	for _, binding := range keys.DashboardShortHelp() {
		help := binding.Help()
		parts = append(parts, help.Key+" "+help.Desc)
	}
	return tui.HelpBarStyle.Render(strings.Join(parts, " • "))
}
