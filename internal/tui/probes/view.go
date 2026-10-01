package probes

import (
	"fmt"

	"ior/internal/probemanager"
	common "ior/internal/tui/common"
)

// searchPromptWidth is the cells of the search input's "/ " prompt;
// searchInputWidth is the widest the search input is drawn.
const (
	searchPromptWidth = 2
	searchInputWidth  = 28
)

// probeLevel is one arrangement of the modal box, from roomy to compact:
// whether the box keeps a blank row of padding above and below its text
// (vpad), separates its sections by blank lines (blanks), wraps the title,
// filter, outcome, error and help lines instead of cutting each to one line
// (the help to whole " • " segments) (wrap), and shows the title with the
// committed filter (title), the family batch's progress or outcome (info)
// and the error (err). The search input, the probe rows and the key help are
// always shown.
type probeLevel struct {
	vpad, blanks, wrap, title, info, err bool
}

// probeLevels lists the arrangements layout tries, roomiest first; the first
// that leaves at least one probe row in the height is drawn. Each sheds one
// thing more: padding, the blank lines, the wrapping, the title, the batch
// line, and last the error. The roomiest is the box the modal always drew,
// so a terminal that fitted it looks as before (task rz2).
var probeLevels = []probeLevel{
	{vpad: true, blanks: true, wrap: true, title: true, info: true, err: true},
	{blanks: true, wrap: true, title: true, info: true, err: true},
	{wrap: true, title: true, info: true, err: true},
	{title: true, info: true, err: true},
	{info: true, err: true},
	{err: true},
	{},
}

// probeLayout is the modal layout for one size and state: the header and
// footer lines around the probe rows (fitted to the text width), whether the
// box is padded vertically, how many rows fit, and the box and text widths.
// bare is set when no box fits (layout): View then draws the bare lines.
type probeLayout struct {
	header, footer []string
	vpad, bare     bool
	rows           int
	boxWidth, text int
}

// size is the terminal size the modal is laid out for (SetSize), with the
// defaults for a size not reported yet.
func (m Model) size() (int, int) {
	width, height := m.width, m.height
	if width <= 0 {
		width = defaultWidth
	}
	if height <= 0 {
		height = defaultHeight
	}
	return width, height
}

// layout computes the modal layout for the current size and state: the
// roomiest of probeLevels whose box leaves at least one probe row in the
// height, the rows being the height minus the box's chrome (border, padding
// and the header and footer lines, already wrapped to the text width, so
// they are counted, not measured). Below seven columns, or when not even
// the most compact box leaves a row, the modal is drawn bare (bareLayout).
// Update keeps the scroll offset with the rows this returns (clampCursor),
// so the selection is always drawn.
func (m Model) layout() probeLayout {
	width, height := m.size()
	boxWidth := probeModalWidth(width)
	text := common.ModalTextWidth(boxWidth, width)
	if width >= common.ModalBoxChrome+1 {
		for _, level := range probeLevels {
			l := probeLayout{header: m.headerLines(level, text), footer: m.footerLines(level, text), vpad: level.vpad, boxWidth: boxWidth, text: text}
			chrome := len(l.header) + len(l.footer) + 2
			if l.vpad {
				chrome += 2
			}
			if l.rows = height - chrome; l.rows >= 1 {
				return l
			}
		}
	}
	return m.bareLayout(height, text)
}

// bareLayout is the layout of a view too small for a box: the search input
// (when searching) first, then one probe row, then the key help, the error,
// the batch line and the title as rows allow (bareRanked), and any rows left
// over go to more probe rows.
func (m Model) bareLayout(height, text int) probeLayout {
	l := probeLayout{bare: true, text: text, boxWidth: text}
	fixed := len(m.bareFooter(text)) + 1 // the footer and the title
	if m.searching && m.view == viewSyscalls {
		fixed++
	}
	l.rows = 1 + max(height-fixed-1, 0)
	return l
}

// bareFooter is the footer of the bare layout: the batch line, the error
// and the help, each on one line.
func (m Model) bareFooter(text int) []string {
	return m.footerLines(probeLevel{info: true, err: true}, text)
}

// layoutTextWidth is the text line's cells at the size SetSize reported.
func (m Model) layoutTextWidth() int {
	width, _ := m.size()
	return common.ModalTextWidth(probeModalWidth(width), width)
}

// visibleRows returns how many probe rows fit on screen (see layout).
func (m Model) visibleRows() int {
	return m.layout().rows
}

// probeModalWidth returns the modal width for the given terminal width: the
// preferred width with a 2-cell margin each side when it fits, shrinking to
// minModalWidth, and below that the whole terminal width, so the box never
// grows wider than the terminal (common.ModalBoxWidth; below seven columns,
// where the box would be wider than the view, the modal is drawn bare).
func probeModalWidth(termWidth int) int {
	return common.ModalBoxWidth(maxModalWidth, minModalWidth, termWidth)
}

// View renders the probe modal centred in a width x height view, exactly
// that size (zero or negative sizes fall back to 80x24). It returns an empty
// string when the modal is not visible. The window of rows starts at the
// offset Update kept for the size reported via SetSize; width and height
// should be that same size.
//
// It used to draw the full box and cut the placed frame with
// MaxHeight/MaxWidth when the chrome alone was taller than the terminal,
// which cut the border, the help and the search input off the bottom
// (task rz2). Now the box sheds what it can spare first (probeLevels) and
// below the most compact box draws the input, a probe row and the help bare
// (bareLayout), so every frame fits by construction.
func (m Model) View(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = defaultWidth
	}
	if height <= 0 {
		height = defaultHeight
	}
	m.width = width
	m.height = height
	l := m.layout()
	lines := m.buildProbeLines(l, m.filtered())
	if l.bare {
		return common.PlaceModal(width, height, l.boxWidth, nil, m.bareRanked(l, lines))
	}
	layout := common.ModalLayout{Lines: lines, VPad: l.vpad}
	return common.PlaceModal(width, height, l.boxWidth, []common.ModalLayout{layout}, nil)
}

// bareRanked ranks the bare layout's lines (rows: the probe rows
// buildProbeLines built) in display order: the title, the search input, the
// rows and the footer. The input ranks first, the rows (all kept together,
// layout counted them) next, then the help, the error, the batch line and
// last the title, so common.KeepRanked keeps exactly what bareLayout
// budgeted.
func (m Model) bareRanked(l probeLayout, rows []string) []common.RankedLine {
	footer := m.bareFooter(l.text)
	last := 2 + len(footer)
	ranked := []common.RankedLine{{Text: m.titleLine(), Rank: last}}
	if m.searching && m.view == viewSyscalls {
		ranked = append(ranked, common.RankedLine{Text: m.searchLine(l.text), Rank: 0})
	}
	for _, row := range rows {
		ranked = append(ranked, common.RankedLine{Text: row, Rank: 1})
	}
	for i, line := range footer {
		// footer ends with the help: it ranks 2, the line before it 3, ...
		ranked = append(ranked, common.RankedLine{Text: line, Rank: last - 1 - i})
	}
	return ranked
}

// titleLine is the modal's heading: the probe counts and the view's name.
func (m Model) titleLine() string {
	active, total := 0, len(m.probes)
	if m.manager != nil {
		active, total = m.manager.ActiveCount()
	}
	title := "Syscalls"
	if m.view == viewFamilies {
		title = "Families"
	}
	return fmt.Sprintf("Probes (%d/%d active) - %s", active, total, title)
}

// searchLine is the search input fitted to a text line text cells wide: its
// "/ " prompt, its window and the cursor (common.FitTextInput, on a copy:
// Update keeps the remembered window, see typeIntoSearch).
func (m Model) searchLine(text int) string {
	common.FitTextInput(&m.textInput, m.inputStart, searchFieldWidth(text))
	return common.InputView(m.textInput, text)
}

// searchFieldWidth is the search input's width for a text line text cells
// wide: at most searchInputWidth, leaving the prompt and the cursor cell.
func searchFieldWidth(text int) int {
	return min(searchInputWidth, text-searchPromptWidth-1)
}

// fitText fits one header or footer line to text cells: wrapped at spaces
// (common.FitWrapped) when wrap is set, else cut to one line ending in "…".
func fitText(line string, text int, wrap bool) []string {
	if wrap {
		return common.FitWrapped(line, text)
	}
	return []string{common.CutLine(line, text, common.Ellipsis)}
}

// headerLines returns the modal lines above the probe rows in level, fitted
// to text cells: the title, the search input or active filter (when any),
// and a spacer. The search input is kept in every level; the title and the
// filter go with level.title.
func (m Model) headerLines(level probeLevel, text int) []string {
	var lines []string
	if level.title {
		lines = append(lines, fitText(m.titleLine(), text, level.wrap)...)
	}
	if m.view == viewSyscalls {
		if m.searching {
			lines = append(lines, m.searchLine(text))
		} else if m.search != "" && level.title {
			// The committed filter text may come from a terminal paste
			// carrying a bidi override, zero-width or blank-rendering rune,
			// which the textinput does not drop, so the display copy is
			// sanitised; m.search itself stays raw because the row filter
			// matches against it.
			lines = append(lines, fitText("Filter: "+common.Sanitize(m.search), text, level.wrap)...)
		}
	}
	if level.blanks && len(lines) > 0 {
		lines = append(lines, "")
	}
	return lines
}

// footerLines returns the modal lines below the probe rows in level, fitted
// to text cells: the running family batch's progress or the last batch's
// outcome, the last toggle error (when any) and the active view's key help,
// each after a blank line when level.blanks is set.
func (m Model) footerLines(level probeLevel, text int) []string {
	var lines []string
	section := func(line string, wrap bool) {
		if level.blanks {
			lines = append(lines, "")
		}
		lines = append(lines, fitText(line, text, wrap)...)
	}
	if level.info {
		if line := m.batchLine(); line != "" {
			section(line, level.wrap)
		} else if m.lastInfo != "" {
			section(common.Sanitize(m.lastInfo), level.wrap)
		}
	}
	if level.err && m.lastErr != "" {
		section("Error: "+common.Sanitize(m.lastErr), level.wrap)
	}
	help := probesHelp
	if m.view == viewFamilies {
		help = familiesHelp
	}
	if level.wrap {
		section(help, true)
	} else {
		if level.blanks {
			lines = append(lines, "")
		}
		lines = append(lines, common.FitHint(help, text))
	}
	return lines
}

// buildProbeLines assembles the modal's lines from a precomputed layout and
// filtered item list: header, the l.rows-high window of rows starting at
// the scroll offset - probes, or in the Families view the families (items is
// then unused) - and the footer. A bare layout has no header or footer here
// (bareRanked adds its lines). Rows are cut to the text width so each takes
// exactly one line, as the row budget assumes.
func (m Model) buildProbeLines(l probeLayout, items []probemanager.ProbeState) []string {
	lines := make([]string, 0, len(l.header)+l.rows+len(l.footer))
	lines = append(lines, l.header...)
	if m.view == viewFamilies {
		lines = append(lines, m.familyRows(l)...)
		return append(lines, l.footer...)
	}
	start := min(m.offset, len(items))
	end := min(start+l.rows, len(items))
	for i := start; i < end; i++ {
		row := m.renderProbeRow(items[i], i == m.cursor)
		lines = append(lines, common.TruncateRight(row, l.text, common.ASCIIEllipsis))
	}
	if len(items) == 0 {
		lines = append(lines, common.CutLine("  (no probes)", l.text, ""))
	}
	return append(lines, l.footer...)
}

// familyRows renders the l.rows-high window of the Families view, each row
// cut to the text width.
func (m Model) familyRows(l probeLayout) []string {
	families := m.familyStates()
	start := min(m.famOffset, len(families))
	end := min(start+l.rows, len(families))
	rows := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		row := renderFamilyRow(families[i], i == m.famCursor)
		rows = append(rows, common.TruncateRight(row, l.text, common.ASCIIEllipsis))
	}
	return rows
}
