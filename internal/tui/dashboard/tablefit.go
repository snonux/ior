package dashboard

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"
)

// tableSpec describes a dashboard table and how it gives way on a terminal
// narrower than its natural layout (task cz2). The columns are the table's
// logical columns at their natural widths: the selected column index, the
// "Col x/N" hint, the sort key of a column (syscallSortKeyForColumn, ...) and
// Enter's filter dimension all refer to them, so fitting the table to the
// width never changes what a column index means. Only the rendering projects
// the rows onto the columns that fit (fitTableColumns).
type tableSpec struct {
	// title names the table in its "terminal too narrow" notice.
	title string
	// columns are the logical columns at their natural widths.
	columns []common.TableColumn
	// flex is the index of the one column that shrinks (and grows into the
	// room dropped columns leave): the name, comm or path. It is never
	// dropped.
	flex int
	// flexMin is the narrowest the flex column may get before the table
	// gives way to the notice.
	flexMin int
	// cut shortens a flex cell to the fitted width, e.g. keeping both ends of
	// a path; nil leaves it to the cell renderer's right cut with "...".
	cut func(value string, width int) string
	// dropOrder lists the optional columns, the first dropped first. A column
	// not listed (the flex column included) is required: the table is shown
	// only while every required column fits.
	dropOrder []int
}

// tableFit is the layout a tableSpec gets at one width: the logical indexes
// of the columns shown, in their logical order, and the width of each.
type tableFit struct {
	visible []int
	widths  []int
}

// minWidth is the narrowest terminal the table is drawn in: every required
// column at its natural width, the flex column at flexMin, and the single
// space between neighbouring columns.
func (s tableSpec) minWidth() int {
	optional := make(map[int]bool, len(s.dropOrder))
	for _, idx := range s.dropOrder {
		optional[idx] = true
	}
	total, count := 0, 0
	for idx, col := range s.columns {
		switch {
		case idx == s.flex:
			total += s.flexMin
		case optional[idx]:
			continue
		default:
			total += col.Width
		}
		count++
	}
	return total + count - 1
}

// tooNarrowNotice is the one-line placeholder a table shows below its
// minWidth, worded like the Flame and histogram notices and cut to the width
// so it never soft-wraps itself.
func (s tableSpec) tooNarrowNotice(width int) string {
	return truncatePlain(fmt.Sprintf("%s: terminal too narrow (need >= %d columns)", s.title, s.minWidth()), width)
}

// fitTableColumns lays the table out for width cells; ok is false when the
// width is below minWidth and the notice is to be shown instead. A table that
// fits at its natural widths (or an unbounded width <= 0) is returned
// unchanged, so wide terminals render exactly as before. Otherwise:
//
//  1. optional columns are dropped in dropOrder until the rest fits beside
//     the flex column at its natural width; the selected column is skipped
//     here, so the cell the user navigated to (and sorts or filters by) stays
//     on screen while anything else can make room;
//  2. the flex column takes whatever is left, which is at least its natural
//     width when step 1 made room and less when every other optional column
//     is gone already;
//  3. only when that is below flexMin is the selected column dropped too (if
//     it is optional), and below that the notice is shown.
//
// The fitted row is therefore never wider than width: the separators are
// counted, and every visible column but the flex one keeps its natural width.
func fitTableColumns(spec tableSpec, width, selectedCol int) (tableFit, bool) {
	natural := naturalTableFit(spec.columns)
	if width <= 0 || tableFitWidth(natural) <= width {
		return natural, true
	}
	hidden := make([]bool, len(spec.columns))
	for _, idx := range spec.dropOrder {
		if nonFlexWidth(spec, hidden)+spec.columns[spec.flex].Width <= width {
			break
		}
		if idx != selectedCol {
			hidden[idx] = true
		}
	}
	if width-nonFlexWidth(spec, hidden) < spec.flexMin && isOptionalColumn(spec, selectedCol) {
		hidden[selectedCol] = true
	}
	flexWidth := width - nonFlexWidth(spec, hidden)
	if flexWidth < spec.flexMin {
		return tableFit{}, false
	}
	var fit tableFit
	for idx, col := range spec.columns {
		switch {
		case hidden[idx]:
			continue
		case idx == spec.flex:
			fit.widths = append(fit.widths, flexWidth)
		default:
			fit.widths = append(fit.widths, col.Width)
		}
		fit.visible = append(fit.visible, idx)
	}
	return fit, true
}

// naturalTableFit is every column at its natural width.
func naturalTableFit(columns []common.TableColumn) tableFit {
	fit := tableFit{visible: make([]int, len(columns)), widths: make([]int, len(columns))}
	for idx, col := range columns {
		fit.visible[idx], fit.widths[idx] = idx, col.Width
	}
	return fit
}

// tableFitWidth is the width of a row laid out by fit: its columns plus one
// separating space between neighbours (common.RenderTableRow joins with " ").
func tableFitWidth(fit tableFit) int {
	total := max(len(fit.widths)-1, 0)
	for _, w := range fit.widths {
		total += w
	}
	return total
}

// nonFlexWidth is the width of a row's shown columns other than the flex one
// plus every separator between the shown columns (the flex column's included),
// i.e. the row width minus the flex column's own width.
func nonFlexWidth(spec tableSpec, hidden []bool) int {
	total, shown := 0, 0
	for idx, col := range spec.columns {
		if hidden[idx] {
			continue
		}
		if idx != spec.flex {
			total += col.Width
		}
		shown++
	}
	return total + shown - 1
}

// isOptionalColumn reports whether idx is in spec's drop order.
func isOptionalColumn(spec tableSpec, idx int) bool {
	for _, opt := range spec.dropOrder {
		if opt == idx {
			return true
		}
	}
	return false
}

// columns returns the shown columns with their fitted widths, in the shape
// common.RenderTableHeader/RenderTableRow take.
func (f tableFit) columns(spec tableSpec) []common.TableColumn {
	out := make([]common.TableColumn, len(f.visible))
	for i, idx := range f.visible {
		out[i] = common.TableColumn{Title: spec.columns[idx].Title, Width: f.widths[i]}
	}
	return out
}

// cells projects one logical row onto the shown columns, cutting the flex
// cell with spec.cut at its fitted width.
func (f tableFit) cells(spec tableSpec, row []string) []string {
	out := make([]string, len(f.visible))
	for i, idx := range f.visible {
		if idx >= len(row) {
			continue
		}
		out[i] = row[idx]
		if idx == spec.flex && spec.cut != nil {
			out[i] = spec.cut(out[i], f.widths[i])
		}
	}
	return out
}

// visibleIndex is the position of logical column idx among the shown ones, or
// -1 when it was dropped (the row is then highlighted without a cell).
func (f tableFit) visibleIndex(idx int) int {
	for i, v := range f.visible {
		if v == idx {
			return i
		}
	}
	return -1
}

// fitHintSegments joins the "[...]" hint segments of a table's last line,
// keeping as many leading segments as fit in width (width <= 0: all). The
// first segment (the "Row x/N Col y/M" position) is always kept, cut to the
// width when even it does not fit; later ones are dropped whole, never cut
// mid-word.
func fitHintSegments(segments []string, width int) string {
	line := "[" + segments[0] + "]"
	if width > 0 && common.DisplayWidth(line) > width {
		return truncatePlain(line, width)
	}
	for _, seg := range segments[1:] {
		next := line + " [" + seg + "]"
		if width > 0 && common.DisplayWidth(next) > width {
			break
		}
		line = next
	}
	return line
}

// fitTableLine cuts a one-line placeholder ("waiting for stats", "no data",
// the Processes PID-filter note) to the width (width <= 0: unbounded), so it
// never draws wider than a narrow terminal; a line that fits is unchanged.
func fitTableLine(line string, width int) string {
	if width <= 0 {
		return line
	}
	return truncatePlain(line, width)
}

// fitPlaceholderLines joins the lines of a chart's empty state (header,
// message, "sel: none") with each one cut to the width by fitTableLine.
func fitPlaceholderLines(width int, lines ...string) string {
	for i, line := range lines {
		lines[i] = fitTableLine(line, width)
	}
	return strings.Join(lines, "\n")
}
