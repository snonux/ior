package export

import (
	"fmt"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// boxCase is a modal state Box is checked in, with the text it must show
// where it has the room and the height of its most compact box.
type boxCase struct {
	name    string
	model   Model
	want    []string
	minRows int
}

// boxCases are the modal's states: live, paused (with the note), with a long
// status message, while exporting (no hint), and paused with a status.
func boxCases() []boxCase {
	open := NewModel().Open()
	paused := NewModel().OpenFor(true)
	done := open
	done.status = "Exported: /var/tmp/ior/some/deep/directory/stream-20261001-123456.csv"
	exporting := open
	exporting.exporting = true
	exporting.status = "Exporting CSV stream rows..."
	pausedDone := paused
	pausedDone.status = "Export failed: disk full"
	hint := []string{"> CSV stream rows", "Cancel", "Enter confirm"}
	return []boxCase{
		{"live", open, hint, 5},
		{"paused", paused, hint, 5},
		{"status", done, append(hint, "Exported:"), 6},
		{"exporting", exporting, []string{"  CSV stream rows", "Cancel", "Exporting"}, 5},
		{"paused+status", pausedDone, append(hint, "Export failed"), 6},
	}
}

// boxWidths are the view widths TestBoxFitsItsArea sweeps: every width up
// to 56 (the box reaches its preferred 48 cells at 52) and two wide views.
func boxWidths() []int {
	widths := make([]int, 0, 58)
	for width := 1; width <= 56; width++ {
		widths = append(widths, width)
	}
	return append(widths, 80, 120)
}

// TestBoxFitsItsArea holds Box to every area from 1x1 to 56x30, and 80 and
// 120 columns, in every modal state (task ns2): it is never wider than the
// area (from seven columns, the narrowest whole box), never taller from its
// most compact height up, always a whole border, and from 30 columns it
// shows the options, the hint (not while exporting) and the status message.
func TestBoxFitsItsArea(t *testing.T) {
	for _, c := range boxCases() {
		t.Run(c.name, func(t *testing.T) {
			for _, width := range boxWidths() {
				for height := 1; height <= 30; height++ {
					assertBoxFits(t, c, width, height)
				}
			}
		})
	}
}

// assertBoxFits checks c's box in a width x height area.
func assertBoxFits(t *testing.T, c boxCase, width, height int) {
	t.Helper()
	box := c.model.Box(width, height)
	where := fmt.Sprintf("%s %dx%d", c.name, width, height)
	lines := strings.Split(box, "\n")
	boxWidth := lipgloss.Width(box)
	if boxWidth > max(width, boxChrome+1) {
		t.Fatalf("%s: box is %d cells wide:\n%s", where, boxWidth, box)
	}
	if !strings.HasPrefix(lines[0], "╭") || !strings.HasPrefix(lines[len(lines)-1], "╰") {
		t.Fatalf("%s: box border is not whole:\n%s", where, box)
	}
	for _, line := range lines {
		if ansi.StringWidth(line) != boxWidth {
			t.Fatalf("%s: ragged box line %q:\n%s", where, line, box)
		}
	}
	if height < c.minRows {
		return
	}
	if got := len(lines); got > height {
		t.Fatalf("%s: box is %d rows tall:\n%s", where, got, box)
	}
	if width < minBoxWidth {
		return
	}
	for _, want := range c.want {
		if !strings.Contains(box, want) {
			t.Fatalf("%s: box lacks %q:\n%s", where, want, box)
		}
	}
}

// TestBoxShedsInOrder pins what Box gives up as the area shrinks: the roomy
// layout (title, blank separators, padding, the whole wrapped paused note)
// where it fits, and the title before the note, the note before the
// options, status and hint.
func TestBoxShedsInOrder(t *testing.T) {
	m := NewModel().OpenFor(true)
	m.status = "Export failed: disk full"
	flat := func(box string) string {
		return strings.Join(strings.Fields(strings.ReplaceAll(box, "│", " ")), " ")
	}
	roomy := m.Box(80, 24)
	for _, want := range []string{title, PausedNote, "Export failed: disk full", hint} {
		if !strings.Contains(flat(roomy), want) {
			t.Fatalf("roomy box lacks %q:\n%s", want, roomy)
		}
	}
	tight := m.Box(80, 7) // border, note, options, status, hint
	if strings.Contains(tight, title) || !strings.Contains(tight, "Live ring") {
		t.Fatalf("a 7-row box must drop the title before the note:\n%s", tight)
	}
	compact := m.Box(80, 6)
	if strings.Contains(compact, "Live ring") || !strings.Contains(compact, "disk full") || !strings.Contains(compact, "Enter confirm") {
		t.Fatalf("a 6-row box must drop the note and keep status and hint:\n%s", compact)
	}
}

// TestFitHintKeepsWholeSegments pins the key hint's narrowing: whole
// segments while the first fits, a marked cut below that.
func TestFitHintKeepsWholeSegments(t *testing.T) {
	cases := map[int]string{
		40: hint,
		26: hint,
		25: "Enter confirm",
		13: "Enter confirm",
		5:  "Ente…",
	}
	for width, want := range cases {
		if got := fitHint(hint, width); got != want {
			t.Fatalf("fitHint(%d) = %q, want %q", width, got, want)
		}
	}
}
