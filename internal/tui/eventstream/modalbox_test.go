package eventstream

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// fitModalCase is one stream input modal in one state.
type fitModalCase struct {
	name string
	view func(width, height int) string
	// hint is the full key hint, which must stay on screen, fitted by whole
	// segments, while the most compact layout fits.
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
		{"search", search.View, "Enter search • Esc cancel", 4},
		{"search+err", searchErr.View, "Enter search • Esc cancel", 5},
		{"export", export.View, "Enter save • Esc cancel", 4},
		{"export+err", exportErr.View, "Enter save • Esc cancel", 5},
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
				if height >= c.compactRows {
					assertModalHint(t, label, out, c.hint, width)
				}
			}
		}
	}
}

// assertModalHint checks that the modal out ends in a whole bottom border
// with the key hint as the last text line above it, fitted by whole
// segments: the longest run of hint's " • " segments that fits the box, or,
// when not even the first one fits, that one cut and ending in "…" (just its
// first letter in a one-cell box). A word cut without a marker ("Esc cance",
// task ls2) fails. The hints are ASCII but for the "•" separator.
func assertModalHint(t *testing.T, label, out, hint string, width int) {
	t.Helper()
	lines := strings.Split(ansi.Strip(out), "\n")
	bottom := -1
	for i, line := range lines {
		if strings.Contains(line, "╰") {
			bottom = i
		}
	}
	got := ""
	for i := bottom - 1; i >= 0 && got == ""; i-- {
		got = strings.TrimSpace(strings.Trim(strings.TrimSpace(lines[i]), "│"))
	}
	if bottom < 0 || got == "" {
		t.Fatalf("%s: bottom border or hint missing:\n%s", label, ansi.Strip(out))
	}
	textWidth := modalBoxWidth(searchModalSize, width) - modalBoxChrome
	if strings.HasPrefix(hint, "Enter save") {
		textWidth = modalBoxWidth(exportModalSize, width) - modalBoxChrome
	}
	segments := strings.Split(hint, " • ")
	want := segments[0]
	switch {
	case lipgloss.Width(want) <= textWidth:
	case textWidth == 1:
		want = want[:1] // common's marker rule: no "…" without a content cell
	default:
		want = want[:textWidth-1] + "…"
	}
	for _, seg := range segments[1:] {
		if lipgloss.Width(want+" • "+seg) > textWidth {
			break
		}
		want += " • " + seg
	}
	if got != strings.TrimSpace(want) {
		t.Fatalf("%s: hint %q, want %q:\n%s", label, got, want, ansi.Strip(out))
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

// modalCursor matches the input cursor in a rendered modal: textinput draws
// it in reverse video over the rune under it, or over a space past the end.
var modalCursor = regexp.MustCompile("\x1b\\[7[;0-9]*m([^\x1b]*)")

// modalInputValues are typed or pasted into the input modals: plain ASCII
// longer than every narrowed box, wide runes (two cells each) mixed with
// ASCII, and a value that always fits.
var modalInputValues = []string{
	"ior-stream-export-with-a-long-name-2026.csv",
	"検索パターン-with-日本語-and-a-long-tail.csv",
	"a.csv",
}

// assertModalCursor checks that the modal out shows the cursor over value's
// rune at pos, or, at the end, over a blank right after value's last rune:
// the cursor, and the end of the typed text while typing, are inside the box.
// Mid-value the input scrolls minimally (the rune before the cursor may be
// scrolled off at the left edge), so only the rune under it is checked; so
// it is when room, the input's cells in the box, cannot hold the last rune
// and the cursor (a wide rune in a two-cell box).
func assertModalCursor(t *testing.T, label, out string, value []rune, pos, room int) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		loc := modalCursor.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		want := " "
		if pos < len(value) {
			want = string(value[pos])
		}
		if got := line[loc[2]:loc[3]]; got != want {
			t.Fatalf("%s: cursor over %q, want %q:\n%s", label, got, want, ansi.Strip(out))
		}
		before := []rune(ansi.Strip(line[:loc[0]]))
		if pos == len(value) && pos > 0 && common.DisplayWidth(string(value[pos-1]))+1 <= room &&
			(len(before) == 0 || before[len(before)-1] != value[pos-1]) {
			t.Fatalf("%s: %q is not right before the cursor:\n%s", label, string(value[pos-1]), ansi.Strip(out))
		}
		return
	}
	t.Fatalf("%s: no cursor drawn:\n%s", label, ansi.Strip(out))
}

// inputModal is a stream input modal reduced to what the cursor tests drive.
type inputModal interface {
	view(width, height int) string
	update(msg tea.Msg) inputModal
}

type searchInput struct{ SearchModal }

func (m searchInput) view(w, h int) string { return m.View(w, h) }
func (m searchInput) update(msg tea.Msg) inputModal {
	m.SearchModal, _, _ = m.Update(msg)
	return m
}

type exportInput struct{ ExportModal }

func (m exportInput) view(w, h int) string { return m.View(w, h) }
func (m exportInput) update(msg tea.Msg) inputModal {
	m.ExportModal, _, _ = m.Update(msg)
	return m
}

// typeAndWalk types value into modal one rune at a time, then walks the
// cursor back to the start, checking that the cursor and the text at it are
// drawn inside the box at width after every stride-th step and at both ends
// (stride 1 checks every step; a larger one keeps the width sweep fast).
func typeAndWalk(t *testing.T, label string, modal inputModal, value []rune, width, room, stride int) {
	t.Helper()
	for i, r := range value {
		modal = modal.update(tea.KeyPressMsg{Code: r, Text: string(r)})
		if (i+1)%stride == 0 || i+1 == len(value) {
			assertModalCursor(t, fmt.Sprintf("%s typed %d", label, i+1), modal.view(width, 12), value[:i+1], i+1, room)
		}
	}
	for pos := len(value) - 1; pos >= 0; pos-- {
		modal = modal.update(tea.KeyPressMsg{Code: tea.KeyLeft})
		if pos%stride == 0 || pos == len(value)-1 {
			assertModalCursor(t, fmt.Sprintf("%s left to %d", label, pos), modal.view(width, 12), value, pos, room)
		}
	}
	// The most compact layout draws the same input line.
	assertModalCursor(t, label+" compact", modal.view(width, 4), value, 0, room)
}

// The search and export inputs scroll their text so the cursor and the text
// it is at stay inside the box at every width the modal is drawn at (task
// ls2). textinput's SetWidth only stores the width, so a box narrower than
// the input's previous width used to keep the old, wider scroll window and
// renderModalBox cut the end of the value and the cursor off (e.g. export at
// 44 columns showed "ior-stream-export-with-a-long-name-202" and no cursor).
// Covered: a modal sized to the view first (Resize, as the stream Model
// does) and one left at its constructor width (View fits a copy).
func TestStreamModalInputKeepsTheCursorInTheBox(t *testing.T) {
	for _, value := range modalInputValues {
		runes := []rune(value)
		// From 8 (export) and 9 (search, one more for its "/") columns the
		// box's text is two cells, the least that holds the cursor and an
		// ASCII rune; below that only the size bounds hold (fitModalCases).
		for width := 8; width <= 80; width++ {
			label := fmt.Sprintf("%q at width %d", value, width)
			stride := 9
			if width < 12 || width%16 == 0 {
				stride = 1
			}
			room := modalBoxWidth(exportModalSize, width) - modalBoxChrome
			typeAndWalk(t, "export resized "+label, exportInput{NewExportModal().Resize(width).Open("")}, runes, width, room, stride)
			// Opened pre-filled, the cursor at the end, as the export default.
			export := NewExportModal().Open(value)
			assertModalCursor(t, "export opened "+label, export.View(width, 20), runes, len(runes), room)
			if width < 9 {
				continue
			}
			room = modalBoxWidth(searchModalSize, width) - modalBoxChrome - searchPrefixWidth
			typeAndWalk(t, "search resized "+label, searchInput{NewSearchModal().Resize(width).Open(SearchForward, "")}, runes, width, room, stride)
			typeAndWalk(t, "search unsized "+label, searchInput{NewSearchModal().Open(SearchBackward, "")}, runes, width, room, stride)
		}
	}
}

// The stream Model sizes the modal inputs with its view (SetViewport, View),
// so typing scrolls them by the width on screen; a pasted value then shows
// its end and the cursor.
func TestStreamModelSizesTheModalInputs(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 3)
	m := NewModel(rb)
	m.Refresh()
	m.SetViewport(30, 20)
	if got, want := m.searchModal.textInput.Width(), searchInputWidth(30); got != want {
		t.Fatalf("search input width %d after SetViewport(30), want %d", got, want)
	}
	if got, want := m.exportModal.textInput.Width(), exportInputWidth(30); got != want {
		t.Fatalf("export input width %d after SetViewport(30), want %d", got, want)
	}
	if !pressLocal(t, &m, "/") || !m.HandlePaste(tea.PasteMsg{Content: modalInputValues[0]}) {
		t.Fatalf("could not open the search modal and paste into it")
	}
	runes := []rune(modalInputValues[0])
	assertModalCursor(t, "model search at 30", m.View(30, 20), runes, len(runes), searchInputWidth(30)+searchPrefixWidth)
	m.View(52, 20)
	if got, want := m.searchModal.textInput.Width(), searchInputWidth(52); got != want {
		t.Fatalf("search input width %d after View(52), want %d", got, want)
	}
}
