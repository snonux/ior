package dashboard

import (
	"fmt"
	"strings"
	"unicode/utf8"

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
	// TabNonIO is the syscall-family summary tab for non-FS families.
	TabNonIO
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
	if width > 0 && width < 90 {
		return renderTabBarPlain(active, width)
	}
	tabs := orderedTabs()
	build := func(short bool) string {
		parts := make([]string, 0, len(tabs))
		for i, tab := range tabs {
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
		label := fmt.Sprintf("%d:%s", tabIndex(active, tabs)+1, tabLabel(active, false))
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
	return common.HelpBarStyle.Width(width).Render(text)
}

func renderHelpHint(width int) string {
	return renderHelpHintWithStatus(width, "")
}

func renderHelpHintWithStatus(width int, status string) string {
	hint := "press H for help"
	if status != "" {
		hint = appendStatusText(hint, status, width)
	}
	if width > 0 && width < 90 {
		return hint
	}
	return common.HelpBarStyle.Width(width).Render(hint)
}

func appendStatusText(base, status string, width int) string {
	if status == "" {
		return base
	}
	line := base + " | " + status
	if width > 0 {
		return truncatePlain(line, width)
	}
	return line
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

// tabLabel returns the display label for tab. When short is true the
// abbreviated name from the registry is used; otherwise the full name.
func tabLabel(tab Tab, short bool) string {
	if !short {
		return tab.String()
	}
	return lookupTab(tab).ShortName
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
		text = truncatePlain(text, width)
		padding := width - utf8.RuneCountInString(text)
		if padding > 0 {
			// Use a Builder to avoid a redundant allocation when right-padding to width.
			var b strings.Builder
			b.Grow(len(text) + padding)
			b.WriteString(text)
			b.WriteString(strings.Repeat(" ", padding))
			return b.String()
		}
	}
	return text
}
