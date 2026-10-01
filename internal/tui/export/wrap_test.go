package export

import (
	"strings"
	"testing"

	common "ior/internal/tui/common"

	"github.com/charmbracelet/x/ansi"
)

// hyphenatedPath is an export path as the exporter writes it: hyphens in
// the temp directory and in the ior-stream-<date>-<time>.csv name.
const hyphenatedPath = "/tmp/TestTUIIntegration-Export/001/ior-stream-20261001-161322.csv"

// TestWrapKeepsAHyphenatedPathWhole pins that the status message breaks
// only at spaces (task ns2): ansi.Wordwrap broke "Exported: <path>" after
// "ior-" although the path fitted a line. Where the path fits it is one
// line; where it does not, it is hard-wrapped into lines filled to the
// width, not broken early at a hyphen. (From nine cells, "Exported:".)
func TestWrapKeepsAHyphenatedPathWhole(t *testing.T) {
	status := "Exported: " + hyphenatedPath
	pathWidth := ansi.StringWidth(hyphenatedPath)
	for width := 9; width <= 120; width++ {
		lines := fitMessage(status, width, true)
		if width >= pathWidth {
			if !containsLine(lines, hyphenatedPath) {
				t.Fatalf("width %d: path broken although it fits: %q", width, lines)
			}
			continue
		}
		pieces := lines[1:] // "Exported:" alone, the path from the next line
		if lines[0] != "Exported:" || strings.Join(pieces, "") != hyphenatedPath {
			t.Fatalf("width %d: path not hard-wrapped whole: %q", width, lines)
		}
		for _, piece := range pieces[:len(pieces)-1] {
			if ansi.StringWidth(piece) != width {
				t.Fatalf("width %d: path broken before the line is full: %q", width, lines)
			}
		}
	}
}

// containsLine reports whether some line of lines contains want.
func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}

// TestWrapNeverLeavesTheNotesDashAlone pins where the " - " of PausedNote
// goes when the note is wrapped (task ns2; ansi.Wordwrap put it on a line of
// its own at 40/41-column terminals, costing a row): at the end of the line
// before when it fits there, else at the start of the next, followed by "use".
// From six cells (the note's longest words, "paused" and "Stream"), it is
// never alone and no word is broken or lost.
func TestWrapNeverLeavesTheNotesDashAlone(t *testing.T) {
	for width := 6; width <= 120; width++ {
		lines := fitMessage(PausedNote, width, true)
		for _, line := range lines {
			if strings.TrimSpace(line) == "-" {
				t.Fatalf("width %d: the dash stands alone: %q", width, lines)
			}
			if ansi.StringWidth(line) > width {
				t.Fatalf("width %d: line %q is too wide", width, line)
			}
		}
		if got := strings.Join(strings.Fields(strings.Join(lines, " ")), " "); got != PausedNote {
			t.Fatalf("width %d: note mangled: %q", width, lines)
		}
	}
	// 30 cells is a 40-column terminal's box: the first line is full, so
	// the dash opens the second.
	want := []string{"Live ring, not the paused view", "- use x on the Stream tab for", "the paused rows"}
	if got := fitMessage(PausedNote, 30, true); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("width 30: got %q, want %q", got, want)
	}
}

// TestWrapShowsTheWholeMessage pins that a wrapped message loses nothing at
// any width (no silent cut): the words of every line, rejoined, are the
// message's, wide runes and long words included, and no line is wider than
// the width (from two cells, the widest rune).
func TestWrapShowsTheWholeMessage(t *testing.T) {
	messages := []string{
		"Export failed: open " + hyphenatedPath + ": permission denied",
		"Exported: /var/tmp/日本語のディレクトリ/ior-stream-20261001-161322.csv",
		PausedNote,
	}
	for _, msg := range messages {
		for width := 2; width <= 80; width++ {
			lines := fitMessage(msg, width, true)
			if got, want := strings.Join(strings.Fields(strings.Join(lines, "")), ""), strings.Join(strings.Fields(msg), ""); got != want {
				t.Fatalf("width %d: message cut: %q", width, lines)
			}
			for _, line := range lines {
				if ansi.StringWidth(line) > width {
					t.Fatalf("width %d: line %q is too wide", width, line)
				}
			}
		}
	}
}

// TestBoxShowsTheWholeStatus pins the same at the box level: in a box with
// room for a wrapping layout, the status message is shown in full, the
// hyphenated path on one line where the box is wide enough for it (from a
// 49-column view for this 39-cell path; the box's text is at most 42 cells
// wide, narrower than hyphenatedPath).
func TestBoxShowsTheWholeStatus(t *testing.T) {
	const shortPath = "/tmp/x-1/ior-stream-20261001-161322.csv"
	m := NewModel().Open()
	m.status = "Exported: " + shortPath
	squash := func(s string) string {
		return strings.Join(strings.Fields(strings.ReplaceAll(s, "│", " ")), "")
	}
	for width := 30; width <= 120; width++ {
		box := m.Box(width, 30)
		if !strings.Contains(squash(box), squash(m.status)) {
			t.Fatalf("width %d: status not shown in full:\n%s", width, box)
		}
		if fitBoxWidth(width)-common.ModalBoxChrome >= ansi.StringWidth(shortPath) && !strings.Contains(box, shortPath) {
			t.Fatalf("width %d: path broken although it fits:\n%s", width, box)
		}
	}
}

// TestBoxHintIsWholeSegments pins that the box fits its key hint by whole
// segments (fitHint) at every width, the awkward ones included where a
// plain cut would show "Enter confirm • Esc cance": the hint line is the
// whole hint, "Enter confirm" alone, or (narrower than that) a cut of
// "Enter confirm".
func TestBoxHintIsWholeSegments(t *testing.T) {
	m := NewModel().Open()
	for width := 7; width <= 120; width++ {
		line := hintLine(m.Box(width, 30))
		switch {
		case line == hint, line != "" && strings.HasPrefix("Enter confirm", strings.TrimSuffix(line, "…")):
		default:
			t.Fatalf("width %d: hint line %q is not whole segments", width, line)
		}
	}
}

// hintLine is the text of box's last text line (the key hint), without the
// border and padding.
func hintLine(box string) string {
	lines := strings.Split(box, "\n")
	for i := len(lines) - 2; i > 0; i-- {
		if text := strings.TrimSpace(strings.Trim(lines[i], "│")); text != "" {
			return text
		}
	}
	return ""
}

// TestViewIsClippedToItsHeight pins View's documented clip: lipgloss.Place
// only pads, so a view shorter than the most compact box would be the box's
// full height without the cut.
func TestViewIsClippedToItsHeight(t *testing.T) {
	m := NewModel().OpenFor(true)
	m.status = "Export failed: disk full"
	for height := 1; height <= 30; height++ {
		if got := len(strings.Split(m.View(40, height), "\n")); got != height {
			t.Fatalf("height %d: view is %d rows tall", height, got)
		}
	}
}
