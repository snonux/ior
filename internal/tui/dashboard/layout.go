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
