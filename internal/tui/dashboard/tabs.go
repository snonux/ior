package dashboard

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
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
	// TabFlame is the live flamegraph tab.
	TabFlame
)

// String returns the full display name of the tab, looked up from the
// central tabDescriptors registry so new tabs need no switch edits here.
func (t Tab) String() string {
	return lookupTab(t).Name
}

func nextTab(tab Tab) Tab {
	tabs := orderedTabs()
	idx := tabIndex(tab, tabs)
	return tabs[(idx+1)%len(tabs)]
}

func prevTab(tab Tab) Tab {
	tabs := orderedTabs()
	idx := tabIndex(tab, tabs)
	if idx == 0 {
		return tabs[len(tabs)-1]
	}
	return tabs[idx-1]
}

func tabIndex(tab Tab, tabs []Tab) int {
	for i, candidate := range tabs {
		if candidate == tab {
			return i
		}
	}
	return 0
}

// renderTabBar renders the full-width styled tab bar. It falls back to the
// plain renderer when the terminal is narrow, and further degrades to showing
// only the active tab label when even the abbreviated labels do not fit.
func renderTabBar(active Tab, width int) string {
	theme := common.Current()
	if width > 0 && width < 90 {
		return renderTabBarPlain(active, width)
	}
	tabs := orderedTabs()
	build := func(short bool) string {
		parts := make([]string, 0, len(tabs))
		for i, tab := range tabs {
			label := fmt.Sprintf("%d:%s", i+1, tabLabel(tab, short))
			if tab == active {
				parts = append(parts, theme.TabActiveStyle.Render(label))
			} else {
				parts = append(parts, theme.TabInactiveStyle.Render(label))
			}
		}
		return lipgloss.JoinHorizontal(lipgloss.Left, parts...)
	}

	bar := build(false)
	if width > 0 && lipgloss.Width(bar) > width {
		bar = build(true)
	}
	if width > 0 && lipgloss.Width(bar) > width {
		label := fmt.Sprintf("%d:%s", tabIndex(active, tabs)+1, tabLabel(active, false))
		bar = theme.TabActiveStyle.Render(label)
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
	return renderHelpBarWithStatus(keys, width, "")
}

func renderHelpBarWithStatus(keys common.KeyMap, width int, status string) string {
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
	if status != "" && len(lines) > 0 {
		lines[len(lines)-1] = appendStatusText(lines[len(lines)-1], status, width)
	}
	text := strings.Join(lines, "\n")
	if width > 0 && width < 90 {
		return text
	}
	return common.Current().HelpBarStyle.Width(width).Render(text)
}

func renderHelpHintWithStatus(width int, status string) string {
	hint := "press H for help"
	if status != "" {
		hint = appendStatusText(hint, status, width)
	}
	if width > 0 && width < 90 {
		return hint
	}
	return common.Current().HelpBarStyle.Width(width).Render(hint)
}

// appendStatusText joins the chrome's static help text and its live status
// half into one row of at most width cells.
//
// When both do not fit, the HELP half is the one that gives way. The status
// half is where the dashboard reports state the user cannot get anywhere else
// - the active filter, a filter that was refused, the recording status - while
// the help half is reference text that the help overlay repeats in full.
// Truncating the joined line from the right (as this did) dropped precisely
// the half worth reading, which is how a refused filter could go unnoticed on
// a narrow terminal.
func appendStatusText(base, status string, width int) string {
	if status == "" {
		return base
	}
	const separator = " | "
	if width <= 0 {
		return base + separator + status
	}
	statusText := truncatePlain(status, width)
	room := width - common.DisplayWidth(statusText) - common.DisplayWidth(separator)
	if room < 1 {
		return statusText
	}
	return truncatePlain(base, room) + separator + statusText
}

// tabLabel returns the display label for tab. When short is true the
// abbreviated name from the registry is used; otherwise the full name.
func tabLabel(tab Tab, short bool) string {
	if !short {
		return tab.String()
	}
	return lookupTab(tab).ShortName
}

// truncatePlain shortens s to at most width display cells, ending in "…" when
// cut. It measures terminal cells rather than runes (common.TruncateRight), so
// wide CJK/emoji text in filter or status strings cannot overflow the row.
// Per the shared marker rule, "…" is added only when it leaves room for
// content: a width of 1 hard-cuts to the first cell ("abc" -> "a"), falling
// back to "…" only when that cell would be half of a wide rune ("日本" -> "…").
func truncatePlain(s string, width int) string {
	return common.TruncateRight(s, width, common.Ellipsis)
}

// renderTabBarPlain renders a plain-text tab bar suitable for narrow terminals.
// Tab order and labels are derived from the registry so no edits are needed
// when new tabs are registered.
func renderTabBarPlain(active Tab, width int) string {
	tabs := orderedTabs()
	parts := make([]string, 0, len(tabs))
	for i, tab := range tabs {
		label := fmt.Sprintf("%d:%s", i+1, tabLabel(tab, true))
		if tab == active {
			label = "[" + label + "]"
		}
		parts = append(parts, label)
	}
	text := strings.Join(parts, " ")
	if width > 0 {
		return common.FitRight(text, width, common.Ellipsis)
	}
	return text
}
