package pidpicker

import (
	"fmt"

	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// noSelection is the selectedIndex of a picker that deliberately highlights
// nothing, and Enter does nothing there. It has two sources: the process the
// user selected vanished in PID mode (relocateUserSelection, with a notice,
// sticky until the user moves), or a selection derived from a non-empty filter
// found the list empty (followFilter's no-match branch, recomputed on every
// rebuild). The latter covers three cases: a filter that matches no process,
// shown with the no-match notice; a failed scan that emptied the list, shown
// with no notice because the scan error line already explains it (applyScan
// holds a derived pid across it, see heldPid); and a filter typed before the
// first scan result arrived, also without a notice, because the empty list only
// means "not loaded yet" (the arriving scan re-derives the selection).
const noSelection = -1

// idNoun names what a picker row is in the current mode, for notices: the TID
// picker lists threads, so "no process matches" would be wrong there.
func (m Model) idNoun() (row, id string) {
	if m.mode == PickerModeTID {
		return "thread", "tid"
	}
	return "process", "pid"
}

// noMatchNotice explains the second noSelection source.
func (m Model) noMatchNotice() string {
	row, _ := m.idNoun()
	return "no " + row + " matches the filter"
}

// moveSelection moves the highlight by delta (-1 up, +1 down), blurs the
// filter input and clears the notice. From noSelection either direction lands
// on the "All" row, so the user then has to either press Enter on All
// deliberately or keep moving to a process; the move is what acknowledges the
// notice, even when it is clamped at the list edge.
//
// Any move makes the selection the user's own (implicit false): from then on
// it is no longer re-derived from the typed filter (followFilter) until an
// edit of the filter text finds it back on the All row (editFilter). That also
// retires a derived pid held across a failed scan (heldPid): only a derived
// selection consults it, and the way back to one is an edit, which drops it.
func (m Model) moveSelection(delta int) Model {
	if m.selectedIndex == noSelection {
		m.selectedIndex = 0
	} else {
		m.selectedIndex = clamp(m.selectedIndex+delta, 0, len(m.filtered))
	}
	m.notice = ""
	m.implicit = false
	m.input.Blur()
	return m
}

// editFilter feeds msg to the filter input and, only when the text really
// changed, rebuilds the list. When the edit happens while the All row is
// highlighted, the highlight is handed back to the filter (implicit true):
// typing "mysql" and pressing Enter then means the first mysql process, not the
// whole system, which is what the untouched All row meant before task hs2. A
// highlighted process row keeps its process (applyFilter ->
// relocateSelection) and a lost-selection noSelection stays sticky, so only the
// All row is handed back, and the user can return to it with Up at any time.
//
// The "text really changed" test matters twice over. A focused input also
// receives messages that do not edit it (Left, Right, Home, End, ctrl+a, an
// empty paste, cursor blinks and any other message the parent forwards), and
// for those the list is not rebuilt at all: rebuilding would re-derive a
// derived selection (followFilter picks row 1) and thereby discard the pid
// tracked across a rescan (applyScan keeps a derived row by pid, which may sit
// on row 2 after a new process sorted ahead of it), so Enter would silently
// emit another pid. And the TID picker can hold a user-owned All row with a
// focused input: a thread the user moved onto and a typed filter then hid
// falls back to All TIDs (relocateUserSelection). That All row is the user's
// own (harmless: it stays in the process, and the user's pick must not
// silently turn into another thread), so cursor movement keeps it, and only
// the next real edit of the text hands it to the filter.
func (m Model) editFilter(msg tea.Msg) (Model, tea.Cmd) {
	before := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.input.Value() == before {
		return m, cmd
	}
	// New text derives a new selection, so a pid held across a failed scan
	// (applyScan) no longer describes what Enter would mean.
	m.heldPid = 0
	if m.selectedIndex == 0 {
		m.implicit = true
	}
	return m.applyFilter(), cmd
}

// emitSelection returns the command announcing the highlighted row. With
// noSelection it returns nil: Enter must not trace anything (in particular not
// the whole system, which the All row means in PID mode) while the picker is
// telling the user that their process is gone or that nothing matches, or while
// a failed scan has emptied the list under a filtered selection (no notice
// then; the scan error line is the explanation, see noSelection).
func (m Model) emitSelection() tea.Cmd {
	if m.selectedIndex == noSelection {
		return nil
	}
	process, onProcess := m.highlightedProcess()
	if m.mode == PickerModeTID {
		// The zero message is the All TIDs row.
		msg := messages.TidSelectedMsg{}
		if onProcess {
			msg = messages.TidSelectedMsg{Pid: process.ParentPID, Tid: process.Pid}
		}
		return func() tea.Msg { return msg }
	}
	// The zero message is the All PIDs row: a whole-system trace.
	msg := messages.PidSelectedMsg{}
	if onProcess {
		msg = messages.PidSelectedMsg{Pid: process.Pid}
	}
	return func() tea.Msg { return msg }
}

// highlightedProcess returns the process row selectedIndex points at. ok is
// false for the "All" row, noSelection and an index outside filtered (e.g.
// before the first scan), none of which has a process identity.
func (m Model) highlightedProcess() (process ProcessInfo, ok bool) {
	idx := m.selectedIndex - 1
	if idx < 0 || idx >= len(m.filtered) {
		return ProcessInfo{}, false
	}
	return m.filtered[idx], true
}

// selectedProcessPid returns the Pid (the tid in TID mode; ProcessInfo.Pid is
// the thread id there) of the process row currently highlighted in filtered.
// ok is false when there is no process row to track, see highlightedProcess.
func (m Model) selectedProcessPid() (pid int, ok bool) {
	process, ok := m.highlightedProcess()
	return process.Pid, ok
}

// relocateSelection re-establishes selectedIndex after filtered was rebuilt;
// queryEmpty tells whether the filter text is empty. A selection the filter
// derives (m.implicit) follows the filter, see followFilter; one the user made
// follows the process, see relocateUserSelection.
func (m Model) relocateSelection(pid int, hadSelection, queryEmpty bool) Model {
	if m.implicit {
		return m.followFilter(queryEmpty)
	}
	return m.relocateUserSelection(pid, hadSelection)
}

// followFilter derives the selection from the filter text alone, for a
// selection the user has not made (initial state, or the All row handed back
// by editFilter):
//   - empty filter: the All row, the initial selection.
//   - matches exist: the first match, row 1. Leaving the All row highlighted
//     would make Enter right after typing a whole-system trace
//     (selectedPIDFilter(0) == -1), the task hs2 bug.
//   - no match: noSelection, which makes Enter a no-op. Falling back to the
//     All row would again make a reflexive Enter trace everything, now for a
//     filter that found nothing. A notice explains it, worded for the picker
//     mode, but only when the empty list really means "nothing matches": not
//     before the first scan arrived (nothing is loaded yet) and not after a
//     failed scan (the list is empty because of the error, which the view
//     shows by itself; applyScan holds the lost derived pid for the next
//     successful scan, see heldPid). Backspacing to a filter with matches
//     re-derives row 1, and Up/Down still reach the All row deliberately.
//
// The derived state is never sticky: every rebuild of the list recomputes it,
// so a rescan that brings the first process of a typed filter selects it
// (applyScan then lets a derived process row keep its identity across a rescan,
// even across a failed one, via heldPid). Note that a derived All row is not
// limited to an empty filter text: a whitespace-only filter trims to the empty
// query and keeps the All row too.
func (m Model) followFilter(queryEmpty bool) Model {
	m.notice = ""
	switch {
	case queryEmpty:
		m.selectedIndex = 0
	case len(m.filtered) > 0:
		m.selectedIndex = 1
	default:
		m.selectedIndex = noSelection
		if m.scanned && m.lastErr == nil {
			m.notice = m.noMatchNotice()
		}
	}
	return m
}

// applyScan installs a scan result and rebuilds the list. A selection derived
// from the filter (m.implicit) normally follows the first match, which would let
// a rescan silently change the pid Enter emits: the highlighted first match
// exited, or a new process sorted ahead of it. So a derived process row is
// tracked by identity across the rescan like a user's pick (keepDerivedProcess),
// but unlike the user's pick it may fall through to the new first match, with a
// notice, since the filter still decides what it means.
//
// A failed scan carries no processes, so it empties the list and a derived
// process row with it (noSelection via followFilter's no-match branch, Enter a
// no-op, only the scan error shown; a derived All row survives, since an empty
// filter derives it without looking at the list). Its pid is kept in heldPid
// and tracked by the next successful scan instead: without that, the empty
// list in between would make that scan see no previous selection, and if the
// pid exited meanwhile the new first match would take over without the notice
// an uninterrupted rescan gives.
func (m Model) applyScan(msg processesLoadedMsg) Model {
	prevPid, tracked := m.trackedDerivedPid()
	m.processes = msg.processes
	m.lastErr = msg.err
	m.scanned = true
	m.heldPid = 0
	m = m.applyFilter()
	switch {
	case tracked && msg.err != nil:
		m.heldPid = prevPid
	case tracked:
		m = m.keepDerivedProcess(prevPid)
	}
	return m
}

// trackedDerivedPid returns the pid of the derived process row a rescan must
// keep by identity: the highlighted one, or the one a failed scan held
// (heldPid). ok is false for a selection the user made (relocateUserSelection
// tracks that) and for a derived All row or no-match state (no process).
func (m Model) trackedDerivedPid() (pid int, ok bool) {
	if !m.implicit {
		return 0, false
	}
	if pid, ok := m.selectedProcessPid(); ok {
		return pid, true
	}
	return m.heldPid, m.heldPid != 0
}

// keepDerivedProcess is applyScan's second half for a derived process row on
// prevPid (applyFilter already re-derived the first match). If prevPid is still
// listed it keeps the selection, wherever the rescan put it; if it left the
// list and the selection moved to another process, a notice names both and
// says why prevPid is gone (goneReason) so the change is not silent. An empty
// result (noSelection plus its own notice) needs nothing here. The notice stays
// until Up/Down or the next recompute.
func (m Model) keepDerivedProcess(prevPid int) Model {
	if m.selectedIndex < 1 || m.filtered[m.selectedIndex-1].Pid == prevPid {
		return m
	}
	for i, process := range m.filtered {
		if process.Pid == prevPid {
			m.selectedIndex = i + 1
			return m
		}
	}
	_, id := m.idNoun()
	m.notice = fmt.Sprintf("%s %d %s - selected %s %d instead",
		id, prevPid, m.goneReason(prevPid), id, m.filtered[m.selectedIndex-1].Pid)
	return m
}

// relocateUserSelection points selectedIndex at the row of pid in the rebuilt
// filtered list. If the process is gone (it exited, or the new query no longer
// matches it) a neighbouring process must not take over, and neither should the
// "All" row silently: in PID mode All means "trace the whole system", so a
// reflexive Enter after the list changed under the user would start a
// system-wide trace without explanation. Instead the picker enters the
// noSelection state (no highlight, Enter is a no-op) and shows a notice until
// the user presses Up/Down. TID mode keeps the plain fallback to the All row:
// "All TIDs" stays within the process (handleTidSelected keeps the current
// pid), so it is never a surprise. When there was no process selected
// (hadSelection false: the user moved onto the All row) the index is only
// clamped into range; an existing noSelection state is sticky across rescans
// and edits until the user moves.
func (m Model) relocateUserSelection(pid int, hadSelection bool) Model {
	if m.selectedIndex == noSelection {
		return m
	}
	if !hadSelection {
		m.selectedIndex = clamp(m.selectedIndex, 0, len(m.filtered))
		return m
	}
	for i, process := range m.filtered {
		if process.Pid == pid {
			m.selectedIndex = i + 1
			return m
		}
	}
	if m.mode == PickerModeTID {
		m.selectedIndex = 0
		return m
	}
	m.selectedIndex = noSelection
	m.notice = m.lostSelectionNotice(pid)
	return m
}

// lostSelectionNotice words why pid left the list, see goneReason.
func (m Model) lostSelectionNotice(pid int) string {
	return fmt.Sprintf("pid %d %s - pick a process", pid, m.goneReason(pid))
}

// goneReason says why pid is not in the filtered list: a process still present
// in the latest scan but filtered out stopped matching the query, anything else
// exited. (It is no longer listed either way, but only the second case means
// the process is gone.)
func (m Model) goneReason(pid int) string {
	for _, process := range m.processes {
		if process.Pid == pid {
			return "no longer matches the filter"
		}
	}
	return "exited"
}
