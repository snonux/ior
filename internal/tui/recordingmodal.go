package tui

import (
	"strings"

	common "ior/internal/tui/common"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// recordingModal is the "Start Parquet Recording" modal: a filename input,
// the last start error and the key hint. It replaces the dashboard while
// open and is fitted to the terminal (View).
type recordingModal struct {
	visible   bool
	textInput textinput.Model
	err       string
	// width is the view width the modal is drawn in, as the last Resize
	// reported (0: not reported, taken as 80); Update fits the input's
	// window to it. inputStart is the rune the input's drawn window starts
	// at, kept so the window stays put while the cursor is drawn in it
	// (common.FitTextInput).
	width      int
	inputStart int
}

const (
	// recordTitle, recordLabel and recordHint are the modal's fixed lines.
	recordTitle = "Start Parquet Recording"
	recordLabel = "Filename:"
	recordHint  = "Enter start" + common.HintSep + "Esc cancel"
	// recordBoxWidth and recordMinBoxWidth are the preferred box width and
	// the narrowest it shrinks to while the view has room
	// (common.ModalBoxWidth); recordInputWidth is the widest the filename
	// input is drawn.
	recordBoxWidth    = 74
	recordMinBoxWidth = 44
	recordInputWidth  = 44
)

func newRecordingModal() recordingModal {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	input.SetWidth(recordInputWidth)
	input.SetStyles(textinput.DefaultStyles(true))
	return recordingModal{textInput: input}
}

func (m recordingModal) Visible() bool {
	return m.visible
}

// TextInputFocused reports whether the modal's path input is receiving typed
// text. The input is focused for as long as the modal is open (Open and
// SetError focus it, Close blurs it), so this equals Visible.
func (m recordingModal) TextInputFocused() bool {
	return m.visible && m.textInput.Focused()
}

func (m recordingModal) SetDarkMode(isDark bool) recordingModal {
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

// Resize fits the filename input to the box drawn in a view width cells
// wide, so Update scrolls the typed text with the width View draws it at.
// The TUI calls it on every size change; zero or negative widths are
// ignored.
func (m recordingModal) Resize(width int) recordingModal {
	if width > 0 {
		m.width = width
		m.inputStart = common.FitTextInput(&m.textInput, m.inputStart, recordFieldWidth(m.width))
	}
	return m
}

func (m recordingModal) Open(defaultPath string) recordingModal {
	m.visible = true
	m.err = ""
	m.textInput.SetValue(defaultPath)
	m.textInput.CursorEnd()
	m.textInput.Focus()
	m.inputStart = common.FitTextInput(&m.textInput, len([]rune(defaultPath)), recordFieldWidth(m.width))
	return m
}

func (m recordingModal) Close() recordingModal {
	m.visible = false
	m.err = ""
	m.textInput.Blur()
	return m
}

func (m recordingModal) SetError(err error) recordingModal {
	if err == nil {
		m.err = ""
		return m
	}
	m.err = err.Error()
	m.visible = true
	m.textInput.Focus()
	return m
}

func (m recordingModal) Update(msg tea.Msg) (recordingModal, string, bool) {
	if !m.visible {
		return m, "", false
	}
	if keyMsg, ok := msg.(tea.KeyPressMsg); ok {
		switch keyMsg.String() {
		case "esc":
			return m.Close(), "", false
		case "enter":
			path := strings.TrimSpace(m.textInput.Value())
			if path == "" {
				m.err = "filename is required"
				return m, "", false
			}
			return m, path, true
		}
	}
	// Every other message edits the path. common.UpdateTextInput, not
	// textInput.Update: bubbles panics on Alt+D on the last rune (task kz2).
	// The window is then re-fitted at the width the last Resize stored, so
	// the cursor stays drawn after the edit (common.FitTextInput).
	var cmd tea.Cmd
	m.textInput, cmd = common.UpdateTextInput(m.textInput, msg)
	_ = cmd
	m.inputStart = common.FitTextInput(&m.textInput, m.inputStart, recordFieldWidth(m.width))
	return m, "", false
}

// recordFieldWidth is the filename input's width in a view width cells wide
// (0: 80): at most recordInputWidth, and one cell less than the modal's text
// line, the cell textinput draws its cursor in past the width.
func recordFieldWidth(width int) int {
	if width <= 0 {
		width = 80
	}
	textWidth := common.ModalTextWidth(common.ModalBoxWidth(recordBoxWidth, recordMinBoxWidth, width), width)
	return min(recordInputWidth, textWidth-1)
}

// View renders the modal centred in a width x height view, exactly that size
// (zero or negative sizes fall back to 80x24). It used to be a fixed
// 74-column box, at least 44 wide, placed with lipgloss.Place, which only
// pads: on a smaller terminal the frame came out taller and wider than the
// screen and the terminal scrolled (task rz2). Now the box is at most the
// view's width (common.ModalBoxWidth, every line cut to it) and sheds, in
// order, its vertical padding, the blank separator lines, the wrapping of
// the error (then one line ending in "…"), the "Filename:" label and the
// title (recordLayouts), keeping the input, the error and the key hint
// (whole " • " segments, common.FitHint) inside a whole border down to four
// rows (five with an error). Below that, or under seven columns, it is drawn
// bare: the input first, then the hint, the error, the title and the label
// as rows allow (recordBareLines).
func (m recordingModal) View(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	boxWidth := common.ModalBoxWidth(recordBoxWidth, recordMinBoxWidth, width)
	textWidth := common.ModalTextWidth(boxWidth, width)
	// m is a copy: the input's window is fitted to this width for this
	// render only, for a caller that skipped Resize; after Resize it is
	// already the remembered one, so this keeps it.
	common.FitTextInput(&m.textInput, m.inputStart, recordFieldWidth(width))
	input := common.InputView(m.textInput, textWidth)
	hint := common.FitHint(recordHint, textWidth)
	return common.PlaceModal(width, height, boxWidth,
		m.recordLayouts(input, hint, textWidth), m.recordBareLines(input, hint, textWidth))
}

// recordError is the error line(s) for a text line textWidth cells wide:
// none without an error, else "Error: <err>" (sanitised: the error echoes
// the typed path) wrapped at whitespace (common.FitWrapped) or, unless wrap
// is set, cut to one line ending in "…".
func (m recordingModal) recordError(textWidth int, wrap bool) []string {
	if m.err == "" {
		return nil
	}
	text := "Error: " + common.Sanitize(m.err)
	if wrap {
		return common.FitWrapped(text, textWidth)
	}
	return []string{common.CutLine(text, textWidth, common.Ellipsis)}
}

// recordLayouts lists the modal's boxes from roomy to compact (see View).
func (m recordingModal) recordLayouts(input, hint string, textWidth int) []common.ModalLayout {
	wrapped, cut := m.recordError(textWidth, true), m.recordError(textWidth, false)
	lines := func(parts ...[]string) []string {
		var out []string
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	head := []string{recordTitle, "", recordLabel, input}
	full := lines(head, wrapped, []string{"", hint})
	return []common.ModalLayout{
		{Lines: full, VPad: true},
		{Lines: full},
		{Lines: lines([]string{recordTitle, recordLabel, input}, wrapped, []string{hint})},
		{Lines: lines([]string{recordTitle, recordLabel, input}, cut, []string{hint})},
		{Lines: lines([]string{recordTitle, input}, cut, []string{hint})},
		{Lines: lines([]string{input}, cut, []string{hint})},
	}
}

// recordBareLines is the modal drawn without a box, ranked for a view too
// small for one: the input (with the cursor) first, then the key hint, the
// error cut to one line, the title and the label.
func (m recordingModal) recordBareLines(input, hint string, textWidth int) []common.RankedLine {
	lines := []common.RankedLine{{Text: recordTitle, Rank: 3}, {Text: recordLabel, Rank: 4}, {Text: input, Rank: 0}}
	for _, line := range m.recordError(textWidth, false) {
		lines = append(lines, common.RankedLine{Text: line, Rank: 2})
	}
	return append(lines, common.RankedLine{Text: hint, Rank: 1})
}
