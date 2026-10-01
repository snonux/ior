package dashboard

import (
	"strings"

	"charm.land/lipgloss/v2"
)

const panelHorizontalChrome = 4

// Keep a small guard so sparkline rows never soft-wrap in panel cells.
const sparklineSafetyMargin = 3

// fitBlocks stacks the pre-rendered blocks top to bottom within height rows.
// Blocks are listed in priority order: a block is kept whole while it fits and
// the first one that does not (plus every block after it) is dropped, so a
// short terminal loses the least important panels instead of showing a panel
// with its bottom border cut off. Only when even the first block is taller
// than height is it clipped, so the result is never taller than height.
// height <= 0 means "unbounded" and keeps every block.
func fitBlocks(blocks []string, height int) string {
	if height <= 0 {
		return strings.Join(blocks, "\n")
	}
	kept := make([]string, 0, len(blocks))
	used := 0
	for _, block := range blocks {
		rows := lipgloss.Height(block)
		if used+rows > height {
			if len(kept) == 0 {
				kept = append(kept, clipLines(block, height))
			}
			break
		}
		kept = append(kept, block)
		used += rows
	}
	return strings.Join(kept, "\n")
}

// clipLines keeps at most the first height lines of s. height <= 0 means
// "unbounded". Panels are rendered line by line with their own style resets,
// so cutting between lines never leaves an escape sequence open.
func clipLines(s string, height int) string {
	if height <= 0 {
		return s
	}
	end := 0
	for range height {
		i := strings.IndexByte(s[end:], '\n')
		if i < 0 {
			return s
		}
		end += i + 1
	}
	return s[:end-1]
}

// minBodyRows is the fewest body rows at which a tab is worth drawing unless
// its descriptor says otherwise (tabDescriptor.MinBodyRows). Below it a table
// has no room for its header plus one row plus its hint, so the body shows a
// one-line "terminal too small" notice instead of a mangled fragment.
const minBodyRows = 3

// Per-tab minimums for the tabs whose smallest complete unit is a panel.
const (
	// altVizMinRows is a bubble, treemap or icicle chart: its header and
	// status lines around a chart that is never shorter than four rows.
	altVizMinRows = 6
	// flameMinRows is the flamegraph's header line, one frame row, the
	// selection line and the status line.
	flameMinRows = 4
	// overviewMinRows is one summary box: five content rows plus borders.
	overviewMinRows = 7
	// latencyMinRows is a histogram panel with a single (folded) bucket row.
	latencyMinRows = histogramChromeRows + 1
	// streamTableMinRows is the stream panel alone: two borders, the status
	// line, the filter line, the column header and one event row. Its footer
	// lines (Row/Sel, status message) are not counted: the stream draws them
	// only into rows the panel leaves free (eventstream.Model.View), so
	// pausing, a status message or the search modal never move the threshold
	// and swap a drawn stream for the notice.
	streamTableMinRows = 6
)

// frameRows is how many terminal rows each part of the dashboard frame gets.
type frameRows struct {
	status, tabBar, body int
}

// splitFrameRows divides height rows among the status block (the help hint
// or expanded help plus the filter/recording status), the tab bar and the tab
// body, in that priority: the status line is the one place state that is
// available nowhere else is reported, the tab bar says where the user is, and
// the body takes whatever is left. The parts never add up to more than height,
// so a short terminal drops the body, then the tab bar, then the upper help
// rows, instead of scrolling the status line off the bottom.
func splitFrameRows(height, statusRows int) frameRows {
	f := frameRows{status: min(statusRows, max(height, 0))}
	rest := max(height, 0) - f.status
	f.tabBar = min(dashboardTabBarRows, rest)
	f.body = rest - f.tabBar
	return f
}

// tooSmallNotice is the body of a terminal with fewer than minBodyRows rows
// to spare, cut to width cells so it never soft-wraps.
func tooSmallNotice(width int) string {
	return truncatePlain("terminal too small", width)
}

// clipTailLines keeps at most the last height lines of s (height <= 0 keeps
// nothing). The status block keeps its tail because the status line is its
// last row.
func clipTailLines(s string, height int) string {
	if height <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= height {
		return s
	}
	return strings.Join(lines[len(lines)-height:], "\n")
}
