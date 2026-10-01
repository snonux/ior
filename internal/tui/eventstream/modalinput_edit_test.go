package eventstream

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// editableModal is an input modal the random edit test can also resize and
// inspect: its value, its cursor position and its box size.
type editableModal interface {
	inputModal
	resize(width int) editableModal
	state() (value []rune, pos int)
	size() modalSize
}

func (m searchInput) resize(width int) editableModal {
	m.SearchModal = m.Resize(width)
	return m
}

func (m searchInput) state() ([]rune, int) {
	return []rune(m.textInput.Value()), m.textInput.Position()
}

func (m searchInput) size() modalSize { return searchModalSize }

func (m exportInput) resize(width int) editableModal {
	m.ExportModal = m.Resize(width)
	return m
}

func (m exportInput) state() ([]rune, int) {
	return []rune(m.textInput.Value()), m.textInput.Position()
}

func (m exportInput) size() modalSize { return exportModalSize }

// modalEditAlphabets are the runes the random edits type and paste: plain
// ASCII, and wide (two-cell) runes mixed with ASCII.
var modalEditAlphabets = map[string][]rune{
	"ascii": []rune("abcdefghijklmnop-._0123456789"),
	"wide":  []rune("検索日本語パタン-ab.cfe"),
}

// modalEditKeys are the cursor and deletion keys the random edits press.
var modalEditKeys = []rune{tea.KeyBackspace, tea.KeyDelete, tea.KeyLeft, tea.KeyRight, tea.KeyHome}

// randomModalEdit applies one random edit to modal: type a rune, paste a
// few, press a key from modalEditKeys or resize the view (and, when sized,
// the modal with it). It returns the modal, the view width and the step's
// label.
func randomModalEdit(rng *rand.Rand, modal editableModal, alphabet []rune, width, minWidth int, sized bool) (editableModal, int, string) {
	switch op := rng.IntN(len(modalEditKeys) + 3); op {
	case 0:
		r := alphabet[rng.IntN(len(alphabet))]
		return modal.update(tea.KeyPressMsg{Code: r, Text: string(r)}).(editableModal), width, "type " + string(r)
	case 1:
		paste := make([]rune, 1+rng.IntN(8))
		for i := range paste {
			paste[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return modal.update(tea.PasteMsg{Content: string(paste)}).(editableModal), width, "paste " + string(paste)
	case 2:
		width = minWidth + rng.IntN(80-minWidth+1)
		if sized {
			// The stream Model resizes the modals on every size change.
			modal = modal.resize(width)
		}
		return modal, width, fmt.Sprintf("resize %d", width)
	default:
		key := modalEditKeys[op-3]
		return modal.update(tea.KeyPressMsg{Code: key}).(editableModal), width, fmt.Sprintf("key %d", key)
	}
}

// assertModalEditCursor checks the input line of out, modal drawn at width:
// the cursor is drawn inside the box over the rune at the cursor position
// (a blank only past the end of the value), and the line is the box's width.
func assertModalEditCursor(t *testing.T, label string, modal editableModal, out string, width int) {
	t.Helper()
	value, pos := modal.state()
	want := " "
	if pos < len(value) {
		want = string(value[pos])
	}
	boxWidth := modalBoxWidth(modal.size(), width)
	for _, line := range strings.Split(out, "\n") {
		loc := modalCursor.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		if got := line[loc[2]:loc[3]]; got != want {
			t.Fatalf("%s: cursor over %q, want %q (value %q, pos %d):\n%s", label, got, want, string(value), pos, ansi.Strip(out))
		}
		stripped := ansi.Strip(line)
		left := strings.Index(stripped, "│")
		if got := lipgloss.Width(strings.TrimSpace(stripped)); left < 0 || got != boxWidth {
			t.Fatalf("%s: input line is %d cells, want the %d-cell box:\n%s", label, got, boxWidth, ansi.Strip(out))
		}
		// The cursor's last cell must lie left of the box's right border.
		cursorEnd := lipgloss.Width(ansi.Strip(line[:loc[3]])) - lipgloss.Width(stripped[:left])
		if cursorEnd > boxWidth-1 {
			t.Fatalf("%s: cursor ends at cell %d of the %d-cell box:\n%s", label, cursorEnd, boxWidth, ansi.Strip(out))
		}
		return
	}
	t.Fatalf("%s: no cursor drawn (value %q, pos %d):\n%s", label, string(value), pos, ansi.Strip(out))
}

// Typing, pasting and deleting in the middle of the value keeps the cursor
// inside the box over the rune it is at (task ls2). textinput recomputes its
// scroll window only when the cursor leaves it, so an insert or a delete
// inside the window left a window that, with two-cell runes, outgrew the
// box (renderModalBox then cut the cursor off: "/検f" with an empty cursor
// at 10 columns) and, after moving right past the window, drew the cursor
// over a blank mid-value. fitModalInput keeps the window drawn when it can
// and moves it as little as the cursor needs; after typing a rune in a sized
// modal that rune stays drawn left of the cursor (assertTypedRuneDrawn).
// Seeded random edit sequences, the input checked after every step, at
// widths from the narrowest that holds a rune and the cursor (8 export, 9
// search) to 80 columns; the third modal is the search left unsized, which
// View alone fits. A resize must keep the value and the cursor position.
func TestStreamModalInputSurvivesMidValueEdits(t *testing.T) {
	const seeds, steps = 45, 120
	for name, alphabet := range modalEditAlphabets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for seed := range seeds {
				runModalEdits(t, fmt.Sprintf("%s seed %d", name, seed), seed, alphabet, steps)
			}
		})
	}
}

// runModalEdits drives one seeded random edit sequence of steps edits. The
// seed picks the modal: export or search sized with the view, or search
// left unsized.
func runModalEdits(t *testing.T, label string, seed int, alphabet []rune, steps int) {
	t.Helper()
	rng := rand.New(rand.NewPCG(uint64(seed), 7))
	var modal editableModal
	minWidth := 9
	switch seed % 3 {
	case 0:
		modal, minWidth = exportInput{NewExportModal().Open("")}, 8
	case 1:
		modal = searchInput{NewSearchModal().Open(SearchForward, "")}
	default:
		modal = searchInput{NewSearchModal().Open(SearchBackward, "")}
	}
	width := minWidth + rng.IntN(80-minWidth+1)
	sized := seed%3 != 2
	if sized {
		modal = modal.resize(width)
	}
	for step := range steps {
		var did string
		value, pos := modal.state()
		modal, width, did = randomModalEdit(rng, modal, alphabet, width, minWidth, sized)
		stepLabel := fmt.Sprintf("%s step %d (%s) at width %d", label, step, did, width)
		// Re-anchoring the window must keep what the user typed and where
		// the cursor is.
		if gotValue, gotPos := modal.state(); strings.HasPrefix(did, "resize") && (string(gotValue) != string(value) || gotPos != pos) {
			t.Fatalf("%s: resize changed %q at %d to %q at %d", stepLabel, string(value), pos, string(gotValue), gotPos)
		}
		assertModalEditCursor(t, stepLabel, modal, modal.view(width, 12), width)
		if sized && strings.HasPrefix(did, "type") {
			assertTypedRuneDrawn(t, stepLabel, modal, width)
		}
	}
}

// assertTypedRuneDrawn checks that the rune just typed into modal, right
// before the cursor, is drawn: the window keeps the text left of the cursor
// rather than starting at it, unless it is too narrow to hold the typed
// rune and the cursor (typedRuneFits).
func assertTypedRuneDrawn(t *testing.T, label string, modal editableModal, width int) {
	t.Helper()
	m := scrollModal{editableModal: modal, room: exportInputWidth(width) + 1}
	if _, ok := modal.(searchInput); ok {
		m.prefix, m.room = searchPrefixWidth, searchInputWidth(width)+1
	}
	_, pos := modal.state()
	if start := m.windowStart(t, label, width); start > pos-1 && typedRuneFits(m, pos-1) {
		t.Fatalf("%s: the typed rune at %d is scrolled off, the window starts at %d", label, pos-1, start)
	}
}
