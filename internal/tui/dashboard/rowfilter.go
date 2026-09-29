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
//   - a directory row stands for its whole subtree, so it becomes the prefix
//     globalfilter.DirPattern (^dir/); aggregateFilesByDir keys rows by the
//     literal directory text (literalDir) so that prefix covers every file
//     the row counts. The noDirGroup row has no such prefix and yields a
//     filter notice instead;
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
//     the PID column is the exact per-process filter.
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
// its family when the Family column is selected.
func handleSyscallsEnter(m *Model) (bool, tea.Cmd) {
	if m.syscallsTab.mode != tabVizModeTable {
		return false, nil
	}
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
	if m.filesTab.mode != tabVizModeTable {
		return false, nil
	}
	if m.filesDirGrouped {
		if selected, ok := m.selectedDirSnapshot(); ok && selected.Dir == noDirGroup {
			m.SetFilterNotice(noDirGroupNotice)
			return true, nil
		}
	}
	return requestSelectedFilter(m.selectedFileFilter())
}

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
	if m.syscallsTab.col == syscallFamilyColumn {
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
		if !usableDir(selected.Dir) {
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

// usableDir reports whether a dir-grouped Files row can become a subtree
// filter. A blank dir cannot, and neither can noDirGroup: it collects
// separator-less names ("a.log", "socket:[123]") and "./"-relative ones, and
// no prefix pattern selects exactly those.
func usableDir(dir string) bool {
	return strings.TrimSpace(dir) != "" && dir != noDirGroup
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
		if comm := strings.TrimSpace(proc.Comm); comm != "" {
			filter.Comm = &globalfilter.StringFilter{Pattern: comm}
			return filter, presenter.DimensionSummary(filter, presenter.DimComm), true
		}
	}
	filter.PID = &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: int64(proc.PID)}
	return filter, presenter.DimensionSummary(filter, presenter.DimPID), true
}
