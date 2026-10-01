package eventstream

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// SearchDirection is which way the stream search scans from the current
// selection.
type SearchDirection int

const (
	// SearchForward scans towards newer rows.
	SearchForward SearchDirection = 1
	// SearchBackward scans towards older rows.
	SearchBackward SearchDirection = -1
)

// SearchModal is the stream tab's search-term entry modal. Like the sibling
// modals it is value-flow: every mutator returns the updated SearchModal.
type SearchModal struct {
	visible   bool
	textInput textinput.Model
	err       string
	direction SearchDirection
}

// NewSearchModal constructs a dark-mode search modal, defaulting to
// forward search.
func NewSearchModal() SearchModal {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	// A default until the stream Model sizes it to its view (Resize).
	input.SetWidth(44)
	input.SetStyles(textinput.DefaultStyles(true))
	return SearchModal{textInput: input, direction: SearchForward}
}

// Visible reports whether the modal is shown.
func (m SearchModal) Visible() bool {
	return m.visible
}

// Direction returns the direction the modal searches in.
func (m SearchModal) Direction() SearchDirection {
	return m.direction
}

// SetDarkMode updates search modal text input styles.
func (m SearchModal) SetDarkMode(isDark bool) SearchModal {
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

// Open shows the modal searching in direction with defaultTerm pre-filled.
func (m SearchModal) Open(direction SearchDirection, defaultTerm string) SearchModal {
	m.visible = true
	m.err = ""
	m.direction = direction
	m.textInput.SetValue(defaultTerm)
	m.textInput.CursorEnd()
	m.textInput.Focus()
	return m
}

// Close hides the modal; the entered term stays in the input and is
// replaced by the next Open.
func (m SearchModal) Close() SearchModal {
	m.visible = false
	m.err = ""
	m.textInput.Blur()
	return m
}

// Update returns updated modal, submitted term, and whether submit occurred.
func (m SearchModal) Update(msg tea.Msg) (SearchModal, string, bool) {
	if !m.visible {
		return m, "", false
	}
	if keyMsg, ok := msg.(tea.KeyPressMsg); ok {
		switch keyMsg.String() {
		case "esc":
			return m.Close(), "", false
		case "enter":
			term := strings.TrimSpace(m.textInput.Value())
			if term == "" {
				m.err = "search term is required"
				return m, "", false
			}
			return m.Close(), term, true
		}
	}
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	_ = cmd
	return m, "", false
}

// searchModalSize is the search box's preferred and smallest width.
var searchModalSize = modalSize{preferred: 58, min: 40}

// searchPrefixWidth is the cells of the "/" or "?" direction prefix drawn
// before the input.
const searchPrefixWidth = 1

// searchInputWidth is the input width of the search box in a view width
// cells wide.
func searchInputWidth(width int) int {
	return modalInputWidth(modalBoxWidth(searchModalSize, width), searchPrefixWidth)
}

// Resize fits the input to the box drawn in a view width cells wide, so
// Update scrolls the typed text with the width View draws it at
// (fitModalInput). The stream Model calls it on every size change and
// render.
func (m SearchModal) Resize(width int) SearchModal {
	if width > 0 {
		fitModalInput(&m.textInput, searchInputWidth(width))
	}
	return m
}

// View renders the centered modal box within the given viewport, fitted to
// it (renderModal): the box and its input line shrink with a narrow view and
// shed their spacing on a short one, so the modal never outgrows the stream
// body it replaces.
func (m SearchModal) View(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	prefix := "/"
	if m.direction == SearchBackward {
		prefix = "?"
	}
	// m is a copy: the input's scroll window is re-anchored for this render
	// only (an edit inside the window leaves it stale, and a caller may have
	// skipped Resize), so the cursor and the rune under it stay visible.
	fitModalInput(&m.textInput, searchInputWidth(width))
	form := modalForm{
		title: "Regex Search",
		label: "Pattern:",
		input: prefix + m.textInput.View(),
		err:   m.err,
		hint:  "Enter search • Esc cancel",
	}
	return renderModal(form, searchModalSize, width, height)
}
