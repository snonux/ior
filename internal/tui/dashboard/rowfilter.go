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
func handleFilesEnter(m *Model) (bool, tea.Cmd) {
	if m.filesTab.mode != tabVizModeTable {
		return false, nil
	}
	return requestSelectedFilter(m.selectedFileFilter())
}

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
	filter.Syscall = &globalfilter.StringFilter{Pattern: selected.Name}
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
		if strings.TrimSpace(selected.Dir) == "" {
			return globalfilter.Filter{}, "", false
		}
		filter.File = &globalfilter.StringFilter{Pattern: selected.Dir}
		return filter, presenter.DimensionSummary(filter, presenter.DimFile), true
	}
	selected, ok := m.selectedFileSnapshot()
	if !ok {
		return globalfilter.Filter{}, "", false
	}
	if strings.TrimSpace(selected.Path) == "" {
		return globalfilter.Filter{}, "", false
	}
	filter.File = &globalfilter.StringFilter{Pattern: selected.Path}
	return filter, presenter.DimensionSummary(filter, presenter.DimFile), true
}

func (m *Model) selectedProcessFilter() (globalfilter.Filter, string, bool) {
	proc, ok := m.selectedProcessSnapshot()
	if !ok || proc.PID == 0 {
		return globalfilter.Filter{}, "", false
	}
	filter := m.globalFilter.Clone()
	if m.processesTab.col == processCommColumn {
		comm := strings.TrimSpace(proc.Comm)
		if comm != "" {
			filter.Comm = &globalfilter.StringFilter{Pattern: comm}
			return filter, presenter.DimensionSummary(filter, presenter.DimComm), true
		}
	}
	filter.PID = &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: int64(proc.PID)}
	return filter, presenter.DimensionSummary(filter, presenter.DimPID), true
}
