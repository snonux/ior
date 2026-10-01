package eventstream

import (
	"fmt"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// fitModalCase is one stream input modal in one state.
type fitModalCase struct {
	name string
	view func(width, height int) string
	// hint is the key hint, which must stay on screen while the most compact
	// layout fits.
	hint string
	// compactRows is the most compact layout's height: border, input, hint,
	// plus the error line when there is one.
	compactRows int
}

func fitModalCases() []fitModalCase {
	search := NewSearchModal().Open(SearchForward, "a-long-search-pattern-that-is-wider-than-a-narrow-box")
	export := NewExportModal().Open("ior-stream-export-with-a-very-long-default-file-name.csv")
	exportErr := export
	exportErr.err = "the export directory does not exist and the name is long"
	searchErr := search
	searchErr.err = "invalid regex: missing closing ) in the pattern"
	return []fitModalCase{
		{"search", search.View, "Enter search", 4},
		{"search+err", searchErr.View, "Enter search", 5},
		{"export", export.View, "Enter save", 4},
		{"export+err", exportErr.View, "Enter save", 5},
	}
}

// The stream modals replace the whole stream body, so they must fit the view
// they are handed: never wider (a wider line soft-wraps in the terminal and
// scrolls the dashboard status line off, task ls2) and never taller, keeping
// the input line, the key hint and a whole bottom border down to their most
// compact layout. Before, the boxes were at least 40 (search) and 44 (export)
// cells wide and always 10 rows tall.
func TestStreamModalsFitTheirView(t *testing.T) {
	for _, c := range fitModalCases() {
		for width := 7; width <= 120; width++ {
			for height := 1; height <= 30; height++ {
				out := c.view(width, height)
				label := fmt.Sprintf("%s %dx%d", c.name, width, height)
				if got := lipgloss.Height(out); got > height {
					t.Fatalf("%s: modal is %d rows:\n%s", label, got, out)
				}
				for i, line := range strings.Split(out, "\n") {
					if w := lipgloss.Width(line); w > width {
						t.Fatalf("%s: line %d is %d cells wide:\n%s", label, i, w, out)
					}
				}
				if height < c.compactRows || width < 30 {
					continue // the hint is cut to the box width below 30 columns
				}
				plain := ansi.Strip(out)
				if !strings.Contains(plain, c.hint) || !strings.Contains(plain, "╰") {
					t.Fatalf("%s: hint or bottom border missing:\n%s", label, plain)
				}
			}
		}
	}
}

// With room to spare the modal keeps its roomy layout and preferred width.
func TestStreamModalKeepsItsFullLayoutWithRoom(t *testing.T) {
	out := NewSearchModal().Open(SearchForward, "").View(100, 30)
	box := strings.TrimSpace(ansi.Strip(out))
	lines := strings.Split(box, "\n")
	if len(lines) != 10 || !strings.Contains(box, "Pattern:") || !strings.Contains(box, "Regex Search") {
		t.Fatalf("search modal at 100x30 is not the full 10-row layout:\n%s", box)
	}
	if w := lipgloss.Width(strings.TrimSpace(lines[0])); w != searchModalSize.preferred {
		t.Fatalf("search modal at 100x30 is %d cells wide, want %d", w, searchModalSize.preferred)
	}
}
