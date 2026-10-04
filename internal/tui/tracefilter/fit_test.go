package tracefilter

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/globalfilter"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// fitWidths and fitHeights are the view sizes the fit sweeps cover (task
// rz2): the one- and seven-column edges of the bare and boxed drawings, a
// few narrow widths and the normal ones, every height up to 30 rows.
var fitWidths = []int{1, 7, 20, 30, 52, 80, 120}

const fitMaxHeight = 30

// wideFilter is a filter whose patterns are CJK and emoji text, so the
// field rows are wider than every narrow box and reach its per-line cut.
func wideFilter() globalfilter.Filter {
	return globalfilter.Filter{
		Family: &globalfilter.StringFilter{Pattern: "fs"},
		Comm:   &globalfilter.StringFilter{Pattern: "日本語😀コマンド名前テスト"},
		File:   &globalfilter.StringFilter{Pattern: "/tmp/絵文字😀😀😀/ファイル名前👩‍👩‍👧.txt"},
	}
}

// press sends key presses for each rune of keys (Enter for '\n').
func press(m Model, keys string) Model {
	for _, r := range keys {
		if r == '\n' {
			m = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
			continue
		}
		m = m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	return m
}

// fitStates are the modal states the sweeps draw, sized to width (Resize,
// as the TUI does) before they are opened and edited.
func fitStates(width int) map[string]Model {
	base := NewModel().Resize(width)
	return map[string]Model{
		"default":      base.Open(globalfilter.Filter{}),
		"wide":         base.Open(wideFilter()),
		"edit-wide":    press(base.Open(wideFilter()), "j\n日本"),
		"edit-file":    press(base.Open(wideFilter()), "jj\n😀x"),
		"edit-numeric": press(base.Open(globalfilter.Filter{}), "jjj\n1234567890123456789012345678"),
		"edit-last":    press(base.Open(globalfilter.Filter{}), "jjjjjjjjjj"),
	}
}

// assertFrame fails unless out is exactly width x height cells, measured
// by lipgloss and by ansi (they disagree on some clusters), every line.
func assertFrame(t *testing.T, label, out string, width, height int) {
	t.Helper()
	lines := strings.Split(out, "\n")
	if len(lines) != height || lipgloss.Height(out) != height {
		t.Fatalf("%s: frame is %d rows, want %d:\n%s", label, len(lines), height, ansi.Strip(out))
	}
	for _, line := range lines {
		if lipgloss.Width(line) != width || ansi.StringWidth(line) != width {
			t.Fatalf("%s: line %q is %d/%d cells, want %d:\n%s", label, ansi.Strip(line),
				lipgloss.Width(line), ansi.StringWidth(line), width, ansi.Strip(out))
		}
	}
}

// TestViewFitsEverySize is the task rz2 regression: the filter box was 23
// rows tall at 80x10 and 26 at 20x5, and 40 columns wide at 20, so the
// terminal scrolled. Every state is drawn at every swept size: the frame is
// exactly the view's size, the active field (with the cursor while editing)
// is always drawn, the key hint from two rows and the whole border from
// four rows (seven columns) up.
func TestViewFitsEverySize(t *testing.T) {
	for _, width := range fitWidths {
		for name, m := range fitStates(width) {
			for height := 1; height <= fitMaxHeight; height++ {
				label := fmt.Sprintf("%s %dx%d", name, width, height)
				out := m.View(width, height)
				assertFrame(t, label, out, width, height)
				assertFilterParts(t, label, m, out, width, height)
			}
		}
	}
}

// assertFilterParts checks the parts of the modal that must be on screen at
// a size: the cursor while editing, else the selection marker; the hint
// from two rows (its first segment from ten columns); the border from four
// rows and seven columns.
func assertFilterParts(t *testing.T, label string, m Model, out string, width, height int) {
	t.Helper()
	plain := ansi.Strip(out)
	if m.editing && !strings.Contains(out, "\x1b[7") {
		t.Fatalf("%s: no cursor drawn:\n%s", label, plain)
	}
	if !m.editing && !strings.Contains(plain, ">") {
		t.Fatalf("%s: no selection marker:\n%s", label, plain)
	}
	if height >= 2 && width >= 10+6 && !strings.Contains(plain, "j/k move") {
		t.Fatalf("%s: key hint missing:\n%s", label, plain)
	}
	boxed := strings.Contains(plain, "╭") && strings.Contains(plain, "╰")
	if want := height >= 4 && width >= 7; boxed != want {
		t.Fatalf("%s: boxed=%v, want %v:\n%s", label, boxed, want, plain)
	}
}

// TestViewShowsEverythingAtNormalSizes pins the normal-size content (the
// look task rz2 kept): title, every field, the Family line, the key help
// and both string-matching notes in a padded box at 80x24 and 120x40.
func TestViewShowsEverythingAtNormalSizes(t *testing.T) {
	m := NewModel().Resize(80).Open(wideFilter())
	for _, size := range [][2]int{{80, 24}, {120, 40}} {
		plain := ansi.Strip(m.View(size[0], size[1]))
		for _, want := range []string{"Filter", "> Syscall:", "Comm:", "Errors:  [ ]", "Family:  fs ([ / ] to change)",
			"j/k move • Enter edit/apply • Tab op • Space toggle errors", "Esc apply+close", "strings: substring by default", "^dir/* = files directly in dir"} {
			if !strings.Contains(plain, want) {
				t.Fatalf("%dx%d: %q missing:\n%s", size[0], size[1], want, plain)
			}
		}
	}
}

// TestViewTypedTextStaysVisible types past the input's width and checks the
// last typed runes (as many as the input is wide: two cells at 20 columns)
// and the cursor are drawn at every width (the input's window follows the
// cursor, common.FitTextInput).
func TestViewTypedTextStaysVisible(t *testing.T) {
	for width, tail := range map[int]string{20: "YZ", 30: "XYZ", 52: "XYZ", 80: "XYZ"} {
		m := press(NewModel().Resize(width).Open(globalfilter.Filter{}), "j\n"+strings.Repeat("abcdefgh", 6)+"XYZ")
		out := m.View(width, 24)
		if !strings.Contains(ansi.Strip(out), tail) || !strings.Contains(out, "\x1b[7") {
			t.Fatalf("width %d: typed tail or cursor not drawn:\n%s", width, ansi.Strip(out))
		}
	}
}

// TestViewNonPositiveSizesAndHidden: a hidden modal draws nothing, and zero
// or negative sizes draw the 80x24 frame without a panic.
func TestViewNonPositiveSizesAndHidden(t *testing.T) {
	if got := NewModel().View(80, 24); got != "" {
		t.Fatalf("hidden modal drew %q", got)
	}
	m := NewModel().Open(wideFilter())
	for _, size := range [][2]int{{0, 0}, {-1, -5}, {0, 24}, {80, -1}} {
		assertFrame(t, fmt.Sprint(size), m.View(size[0], size[1]), 80, 24)
	}
}
