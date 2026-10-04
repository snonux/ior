package dashboard

import (
	"strings"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// This file turns a table tab's selected row into a global filter request:
// the tabs' HandleEnter hooks (registered in tabregistry.go) and the
// row->filter builders behind them. Each builder narrows a clone of the
// active global filter by one dimension of the selected row and returns the
// filter, a one-line summary of the dimension it set, and whether the row
// yields a usable filter at all.
//
// A row filter selects what the row counts. For a syscall or file row that is
// exactly the row's value, never a substring of it: Enter on the syscall
// "read" must not also admit readv/pread64, on file "/tmp/a" not also
// "/tmp/ab" or "/var/tmp/a". So those builders emit globalfilter.ExactPattern
// (^value$), which also keeps a value's leading/trailing blanks and edge ^/$
// characters literal instead of letting the matcher trim them or read them
// as anchors. Three dimensions differ on purpose:
//   - a directory row counts only the files directly in its directory
//     (the engine's directory ranking keys rows by the literal directory text,
//     statsengine.DirOf), so it becomes the directory-children pattern
//     globalfilter.DirPattern (^dir/*), which the matcher defines by that
//     same literal directory text: files of subdirectories (their own rows)
//     are not selected, and the "/" row selects only top-level entries. Like
//     ^exact$ it is case-sensitive. The noDirGroup row and the
//     remainder ("other") row have no such pattern and yield a filter
//     notice instead;
//   - a family row keeps the bare family name: families are a closed set in
//     which no name contains another, so bare is already exact, and the
//     [/] family cycle (familycycle.go) identifies the current family by its
//     bare name;
//   - a process's Comm cell stays a (trimmed) substring pattern. The row
//     aggregates every thread of the PID but shows only the leader's (or
//     first-seen) comm, while the comm filter is matched per event against
//     the thread's own comm. Threads are commonly named after their process
//     ("chrome" -> "Chrome_ChildIOT", matched case-insensitively), so the substring keeps them; an exact
//     pattern would drop them although the row counted them. It remains an
//     approximation either way ("Web Content" threads are missed by both):
//     the PID column is the exact per-process filter. A comm starting with
//     ^ or ending with $ cannot be a literal substring pattern, so that row
//     falls back to the PID filter (commSubstringUsable). The Stream tab's
//     Comm cell, by contrast, is exact (eventstream setStringCellFilter):
//     a Stream row is one event, so its comm is that event's own thread comm.
//
// Typed patterns (filter modal, -comm/-path flags) stay substring searches.

// syscallFamilyColumn is the index of the Family column in the Syscalls table
// (right after the Syscall name column, in both the compact and full layouts).
// Enter on this column scopes the dashboard to the selected row's family rather
// than its syscall name.
const syscallFamilyColumn = 1

// processCommColumn is the index of the Comm column in the Processes table
// (right after the PID column). Enter on this column filters by the selected
// row's command name rather than its PID.
const processCommColumn = 1

// handleSyscallsEnter is the Syscalls tab's HandleEnter hook: Enter on the
// selected row requests a global filter on that row's syscall name, or on
// its family when the Family column is selected. In the bubbles and treemap
// views the selected row is the highlighted bubble or tile, and the filter
// is always by name: those views have no columns, and the table's column
// selection must not turn Enter into a family filter there (task cr2).
func handleSyscallsEnter(m *Model) (bool, tea.Cmd) {
	return requestSelectedFilter(m.selectedSyscallFilter())
}

// handleFilesEnter is the Files tab's HandleEnter hook, covering both the
// dir-grouped and the plain sub-table.
//
// Enter on the noDirGroup row is handled without a request: no filter
// selects exactly its members, and staying silent read as a broken key, so
// it explains that in the filter notice instead. The notice is cleared like
// any refusal notice, by the next filter change on screen.
func handleFilesEnter(m *Model) (bool, tea.Cmd) {
	if m.filesDirGrouped {
		if selected, ok := m.selectedDirSnapshot(); ok {
			if notice := dirRowRefusalNotice(selected); notice != "" {
				m.SetFilterNotice(notice)
				return true, nil
			}
		}
	}
	return requestSelectedFilter(m.selectedFileFilter())
}

// dirRowRefusalNotice returns the notice explaining why Enter on the dir row
// sets no filter, or "" when the row can become one.
func dirRowRefusalNotice(row DirSnapshot) string {
	switch {
	case row.IsRemainder():
		return otherDirsNotice
	case !usableDir(row.Dir):
		return noDirGroupNotice
	}
	return ""
}

// otherDirsNotice is the filter notice for Enter on the remainder row, which
// sums many directories that share no filterable pattern.
const otherDirsNotice = `NO FILTER (the "(other)" row sums the directories outside the top ranked ones) - keeping the current filter`

// noDirGroupNotice is the filter notice for Enter on the noDirGroup row,
// worded like the TUI's refusal notice ("FILTER REFUSED (...) - keeping the
// previous filter").
const noDirGroupNotice = `NO FILTER (the "." group mixes names with no common path prefix) - keeping the current filter`

// handleProcessesEnter is the Processes tab's HandleEnter hook. Enter also
// works from the treemap and bubbles views there: both select whole rows,
// so the filter request is well-defined in every mode.
func handleProcessesEnter(m *Model) (bool, tea.Cmd) {
	return requestSelectedFilter(m.selectedProcessFilter())
}

// requestSelectedFilter turns a tab's selected-row filter into the standard
// GlobalFilterRequestedMsg command; the shared shape of every table tab's
// HandleEnter hook.
func requestSelectedFilter(filter globalfilter.Filter, action string, ok bool) (bool, tea.Cmd) {
	if !ok {
		return false, nil
	}
	return true, func() tea.Msg { return messages.GlobalFilterRequestedMsg{Filter: filter, Action: action} }
}

func (m *Model) selectedSyscallFilter() (globalfilter.Filter, string, bool) {
	selected, ok := m.selectedSyscallSnapshot()
	if !ok {
		return globalfilter.Filter{}, "", false
	}
	if m.syscallsTab.mode == tabVizModeTable && m.syscallsTab.col == syscallFamilyColumn {
		family := string(selected.TraceID.Family())
		if strings.TrimSpace(family) == "" {
			return globalfilter.Filter{}, "", false
		}
		filter := m.globalFilter.Clone()
		filter.Family = &globalfilter.StringFilter{Pattern: family}
		return filter, presenter.DimensionSummary(filter, presenter.DimFamily), true
	}
	if strings.TrimSpace(selected.Name) == "" {
		return globalfilter.Filter{}, "", false
	}
	filter := m.globalFilter.Clone()
	filter.Syscall = &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern(selected.Name)}
	return filter, presenter.DimensionSummary(filter, presenter.DimSyscall), true
}

func (m *Model) selectedFileFilter() (globalfilter.Filter, string, bool) {
	if m.latest == nil {
		return globalfilter.Filter{}, "", false
	}
	filter := m.globalFilter.Clone()
	if m.filesDirGrouped {
		selected, ok := m.selectedDirSnapshot()
		if !ok {
			return globalfilter.Filter{}, "", false
		}
		if selected.IsRemainder() || !usableDir(selected.Dir) {
			return globalfilter.Filter{}, "", false
		}
		filter.File = &globalfilter.StringFilter{Pattern: globalfilter.DirPattern(selected.Dir)}
		return filter, presenter.DimensionSummary(filter, presenter.DimFile), true
	}
	selected, ok := m.selectedFileSnapshot()
	if !ok {
		return globalfilter.Filter{}, "", false
	}
	if strings.TrimSpace(selected.Path) == "" {
		return globalfilter.Filter{}, "", false
	}
	filter.File = &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern(selected.Path)}
	return filter, presenter.DimensionSummary(filter, presenter.DimFile), true
}

// usableDir reports whether a dir-grouped Files row can become a
// directory-children filter. Only noDirGroup cannot: it collects
// separator-less names ("a.log", "socket:[123]") together with "./"-relative
// ones, and no pattern selects exactly that mix ("^./*" would miss the
// separator-less names). Every other dir can, even an all-blank one ("   "
// from "   /z"): DirPattern writes it as "^   /*", which no trim alters.
func usableDir(dir string) bool {
	return dir != noDirGroup
}

func (m *Model) selectedProcessFilter() (globalfilter.Filter, string, bool) {
	proc, ok := m.selectedProcessSnapshot()
	if !ok || proc.PID == 0 {
		return globalfilter.Filter{}, "", false
	}
	filter := m.globalFilter.Clone()
	if m.processesTab.col == processCommColumn {
		// A substring, not ExactPattern: the row counts every thread of the
		// PID, and thread comms often extend the process's (see the file
		// comment). Trimmed, since the matcher trims a pattern anyway and the
		// action label should read the same as the applied filter.
		if comm := strings.TrimSpace(proc.Comm); commSubstringUsable(comm) {
			filter.Comm = &globalfilter.StringFilter{Pattern: comm}
			return filter, presenter.DimensionSummary(filter, presenter.DimComm), true
		}
	}
	// The PID filter is exact per PID, not per row: when the kernel recycled
	// the PID during the session the table has one row per lifetime
	// (ProcessSnapshot.Lifetime), and the filter matches all of them, since
	// events carry no lifetime to narrow on. From then on only the process
	// currently holding the PID produces events, so that is what it scopes.
	filter.PID = &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: int64(proc.PID)}
	return filter, presenter.DimensionSummary(filter, presenter.DimPID), true
}

// commSubstringUsable reports whether a trimmed comm can serve as the Comm
// cell's substring pattern. A blank one cannot (it constrains nothing), and
// neither can one starting with ^ or ending with $: the matcher would read
// that character as an anchor ("x$" = "ends with x"), and a substring pattern
// has no way to keep it literal. Such a row falls back to the PID filter,
// which is the exact filter for the process anyway.
func commSubstringUsable(comm string) bool {
	return comm != "" && !strings.HasPrefix(comm, "^") && !strings.HasSuffix(comm, "$")
}
