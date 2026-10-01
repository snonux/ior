package eventstream

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"ior/internal/tui/common"
)

// scrollModal is an input modal the scroll tests drive like the stream Model
// does (an update, then a Resize before every render) and whose drawn
// scroll window they read back.
type scrollModal struct {
	editableModal
	// prefix is the cells drawn before the input text in the box ("/").
	prefix int
	// room is the cells the input's window may fill: its width and the
	// cursor cell (modalInputWidth).
	room int
}

// step applies msg, resizes to width as the stream Model does on every
// render, and returns the modal and its drawn window start.
func (m scrollModal) step(t *testing.T, label string, msg tea.Msg, width int) (scrollModal, int) {
	t.Helper()
	m.editableModal = m.update(msg).(editableModal).resize(width)
	return m, m.windowStart(t, label, width)
}

// windowStart renders m at width and returns the index of the first rune of
// the value drawn in its input line: the cells drawn between the box's text
// start and the cursor are the widths of the runes from there to the cursor.
// It fails the test when the cursor is not drawn over the rune at the
// cursor position (assertModalEditCursor).
func (m scrollModal) windowStart(t *testing.T, label string, width int) int {
	t.Helper()
	out := m.view(width, 12)
	assertModalEditCursor(t, label, m.editableModal, out, width)
	value, pos := m.state()
	for _, line := range strings.Split(out, "\n") {
		loc := modalCursor.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		stripped := ansi.Strip(line)
		left := strings.Index(stripped, "│")
		// The text starts after the border, two cells of padding and the
		// prefix.
		textStart := lipgloss.Width(stripped[:left]) + 1 + 2 + m.prefix
		cells := lipgloss.Width(ansi.Strip(line[:loc[0]])) - textStart
		for start, drawn := pos, 0; start >= 0; start-- {
			if drawn == cells {
				return start
			}
			if start > 0 {
				drawn += common.DisplayWidth(string(value[start-1]))
			}
		}
		t.Fatalf("%s: %d cells before the cursor match no window of %q at %d:\n%s", label, cells, string(value), pos, ansi.Strip(out))
	}
	t.Fatalf("%s: no cursor drawn:\n%s", label, ansi.Strip(out))
	return 0
}

// scrollModals returns the export and search modals opened with value and
// sized to width, and the narrowest width each holds a rune and the cursor
// at (8 for export, 9 for search with its "/").
func scrollModals(value string, width int) []scrollModal {
	modals := []scrollModal{{
		editableModal: exportInput{NewExportModal().Resize(width).Open(value)},
		room:          exportInputWidth(width) + 1,
	}}
	if width >= 9 {
		modals = append(modals, scrollModal{
			editableModal: searchInput{NewSearchModal().Resize(width).Open(SearchForward, value)},
			prefix:        searchPrefixWidth,
			room:          searchInputWidth(width) + 1,
		})
	}
	return modals
}

// scrollValue is a value of n runes cycling through alphabet, long enough to
// scroll in every box up to 80 columns.
func scrollValue(alphabet []rune, n int) string {
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = alphabet[i%len(alphabet)]
	}
	return string(runes)
}

// typedRuneFits reports whether m's window can hold the rune typed at pos
// and the cursor after it (over the next rune, or a blank at the end): a
// wide rune in a two- or three-cell window cannot, so the window has to
// start at the cursor and the typed rune scrolls off.
func typedRuneFits(m scrollModal, pos int) bool {
	value, _ := m.state()
	cursor := 1
	if pos+1 < len(value) {
		cursor = common.DisplayWidth(string(value[pos+1]))
	}
	return common.DisplayWidth(string(value[pos]))+cursor <= m.room
}

// The reviewer's case (task ls2): export at 60 columns, a 64-rune value, the
// cursor moved 55 runes left, "NEW" typed and the modal resized as the stream
// Model does on every render. Re-anchoring the window on every render moved
// it to start at the cursor, so "NEW" was scrolled off the left edge; the
// window has to stay put and show "NEW" right before the cursor.
func TestStreamModalInputShowsMidValueTyping(t *testing.T) {
	value := scrollValue([]rune("abcdefghij"), 64)
	m := scrollModal{editableModal: exportInput{NewExportModal().Resize(60).Open(value)}}
	for range 55 {
		m, _ = m.step(t, "left", tea.KeyPressMsg{Code: tea.KeyLeft}, 60)
	}
	for _, r := range "NEW" {
		m, _ = m.step(t, "type", tea.KeyPressMsg{Code: r, Text: string(r)}, 60)
	}
	if out := ansi.Strip(m.view(60, 12)); !strings.Contains(out, "NEWjabcdefghij") {
		t.Fatalf("typed %q is not drawn before the cursor:\n%s", "NEW", out)
	}
}

// The input window scrolls minimally (task ls2): walking the cursor left
// through a long value moves the window only when the cursor leaves its left
// edge, and then by one rune; walking right moves it only when the cursor
// passes its right edge, and then by no more than two runes (a wide rune
// coming in can push out two narrow ones). Typing a rune mid-value keeps the
// typed rune drawn (the window never starts past it, unless the window is
// too narrow for it and the cursor) and the window moves by at most two
// runes. ASCII and wide runes, export and search, every width from 8 to 16
// columns (where a wide rune nearly fills the box) and a spread up to 80,
// with a value about three boxes long; the cursor is checked over the right
// rune at every step.
func TestStreamModalInputScrollsMinimally(t *testing.T) {
	widths := []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 21, 29, 37, 44, 52, 63, 80}
	for name, alphabet := range modalEditAlphabets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, width := range widths {
				value := scrollValue(alphabet, 3*width/2+10)
				for _, m := range scrollModals(value, width) {
					label := fmt.Sprintf("%s %T at width %d", name, m.editableModal, width)
					m = assertMinimalWalk(t, label, m, width)
					assertMidValueTyping(t, label, m, alphabet, width)
				}
			}
		})
	}
}

// assertMinimalWalk walks the cursor from the end of m's value to its start
// and back, checking the window moves minimally, and returns m with the
// cursor back at the end.
func assertMinimalWalk(t *testing.T, label string, m scrollModal, width int) scrollModal {
	t.Helper()
	value, _ := m.state()
	start := m.windowStart(t, label+" opened", width)
	for pos := len(value) - 1; pos >= 0; pos-- {
		prev := start
		m, start = m.step(t, fmt.Sprintf("%s left to %d", label, pos), tea.KeyPressMsg{Code: tea.KeyLeft}, width)
		if start != prev && start != pos {
			t.Fatalf("%s left to %d: window moved from %d to %d, want it kept or at the cursor", label, pos, prev, start)
		}
	}
	for pos := 1; pos <= len(value); pos++ {
		prev := start
		m, start = m.step(t, fmt.Sprintf("%s right to %d", label, pos), tea.KeyPressMsg{Code: tea.KeyRight}, width)
		if start < prev || start > prev+2 {
			t.Fatalf("%s right to %d: window moved from %d to %d, want at most two runes right", label, pos, prev, start)
		}
	}
	return m
}

// assertMidValueTyping moves the cursor a random stride left and types a
// rune, a dozen times, checking the typed rune stays drawn and the
// window moves by at most two runes.
func assertMidValueTyping(t *testing.T, label string, m scrollModal, alphabet []rune, width int) {
	t.Helper()
	rng := rand.New(rand.NewPCG(uint64(width), 11))
	for i := range 12 {
		// The cursor walk is checked by assertMinimalWalk: here only the
		// model is stepped, and the window read once before typing.
		for range rng.IntN(width) {
			m.editableModal = m.update(tea.KeyPressMsg{Code: tea.KeyLeft}).(editableModal).resize(width)
		}
		prev := m.windowStart(t, label, width)
		_, pos := m.state()
		r := alphabet[rng.IntN(len(alphabet))]
		stepLabel := fmt.Sprintf("%s typing %d (%q at %d)", label, i, r, pos)
		var start int
		m, start = m.step(t, stepLabel, tea.KeyPressMsg{Code: r, Text: string(r)}, width)
		if start > pos && typedRuneFits(m, pos) {
			t.Fatalf("%s: the typed rune at %d is scrolled off, the window starts at %d", stepLabel, pos, start)
		}
		if start < prev || start > prev+2 {
			t.Fatalf("%s: window moved from %d to %d, want at most two runes right", stepLabel, prev, start)
		}
	}
}
