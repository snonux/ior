package probes

import (
	"fmt"

	"ior/internal/probemanager"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// view selects what the modal lists: single syscall probes or whole families.
type view uint8

const (
	viewSyscalls view = iota
	viewFamilies
)

// familiesHelp is the footer key help of the Families view.
const familiesHelp = "j/k move • space|enter attach/detach family • tab syscalls • esc close"

// familyBatch is the family attach/detach in flight, as last reported.
type familyBatch struct {
	active    bool
	family    types.SyscallFamily
	attach    bool
	completed int
	total     int
}

// NotTracedHint returns the status hint for a dashboard scoped to family
// while none of its probes is attached - the view would otherwise just be
// empty with no explanation. It returns "" when family is empty (unscoped),
// has at least one active probe, or has no probe at all on this kernel (there
// is nothing to attach, so the hint's instructions would lead nowhere).
//
// The instructions are literal: the TUI opens the modal with the Families
// cursor on the scoped family (FocusFamily), so O, tab, space attach exactly
// this family. The hint names the capital O rather than o because it is shown
// on every tab, and the Flame tab (the default) consumes lowercase o as its
// frame-order key, so o would do nothing there; O opens the modal everywhere.
func NotTracedHint(family string, states []probemanager.ProbeState) string {
	if family == "" {
		return ""
	}
	for _, state := range probemanager.FamilyStates(states) {
		if string(state.Family) == family && (state.Active > 0 || state.Total == 0) {
			return ""
		}
	}
	return family + " not traced: press O, tab, space to attach"
}

// FocusFamily puts the Families view cursor on family (the view itself is
// not switched), so the dashboard's family scope is preselected when the
// user tabs over. An unknown family leaves the cursor unchanged.
func (m Model) FocusFamily(family string) Model {
	for i, candidate := range types.AllSyscallFamilies() {
		if string(candidate) == family {
			m.famCursor = i
		}
	}
	return m.clampCursor()
}

// ShowBatchProgress displays the progress of the running family batch. It
// only renders: following the batch (FamilyBatchProgressMsg.Next) is up to
// the TUI, which owns the run and replays the last progress into a rebuilt
// modal through this method.
func (m Model) ShowBatchProgress(msg FamilyBatchProgressMsg) Model {
	m.batch = familyBatch{active: true, family: msg.Family, attach: msg.Attach, completed: msg.Completed, total: msg.Total}
	return m.clampCursor()
}

// FinishBatch ends the displayed family batch: it reloads the probe list and
// reports how many probes were attached or detached and, if any reported an
// error, the first one (those probes also carry their error in the Syscalls
// view rows; see familyOutcome for what the counts mean). A non-empty note
// is appended to the outcome line.
func (m Model) FinishBatch(msg FamilyToggledMsg, note string) Model {
	m.batch = familyBatch{}
	m = m.reload()
	m.lastInfo, m.lastErr = familyOutcome(msg)
	if note != "" {
		m.lastInfo += " " + note
	}
	return m.clampCursor()
}

// SetError shows err in the modal's error line.
func (m Model) SetError(err string) Model {
	m.lastErr = err
	return m.clampCursor()
}

// familyStates returns the per-family counts of the loaded probe list.
func (m Model) familyStates() []probemanager.FamilyState {
	return probemanager.FamilyStates(m.probes)
}

// switchView toggles between the Syscalls and Families views. Search is a
// Syscalls-view feature, so its filter line only shows there; the row budget
// is re-derived for the new chrome.
func (m Model) switchView() Model {
	if m.view == viewFamilies {
		m.view = viewSyscalls
	} else {
		m.view = viewFamilies
	}
	return m.clampCursor()
}

// toggleSelectedFamily requests detaching the selected family when any of
// its probes is attached and attaching it otherwise. A key press while a
// batch is shown as running is ignored here; the TUI, which owns the run,
// refuses overlapping requests too (the modal may have been rebuilt). The
// provisional progress total is the number of probes the batch has to
// change: the attached ones for a detach, the detached ones for an attach.
func (m Model) toggleSelectedFamily() (Model, tea.Cmd) {
	families := m.familyStates()
	if m.batch.active || m.famCursor < 0 || m.famCursor >= len(families) {
		return m, nil
	}
	state := families[m.famCursor]
	if state.Total == 0 {
		m.lastErr = fmt.Sprintf("%s has no probes on this kernel", state.Family)
		return m.clampCursor(), nil
	}
	attach := state.Active == 0
	total := state.Active
	if attach {
		total = state.Total - state.Active
	}
	m.batch = familyBatch{active: true, family: state.Family, attach: attach, total: total}
	m.lastErr = ""
	m.lastInfo = ""
	request := FamilyBatchRequestMsg{Family: state.Family, Attach: attach}
	return m.clampCursor(), func() tea.Msg { return request }
}

// familyOutcome returns the info and error text for a finished family batch.
//
// The two operations count differently. A probe whose attach failed stayed
// detached, so an attach reports the probes that changed without an error
// ("attached 1 of 2 probes") and the others as failed. A probe whose detach
// reported an error is detached like the rest - a link's Destroy is final,
// whatever it returns (probemanager.Link, BatchResult) - so a detach counts
// it among the detached ("detached 3 of 3 probes") and only says that it
// reported an error: "detached 2 of 3" and "1 failed" told the user that a
// probe was still attached, and the Families row beside it showed 0 attached.
func familyOutcome(msg FamilyToggledMsg) (info, errText string) {
	if msg.Err != nil {
		return "", fmt.Sprintf("%s: %v", msg.Family, msg.Err)
	}
	result := msg.Result
	done, failure := result.Changed, "failed"
	if !msg.Attach {
		done, failure = result.Changed+len(result.Errors), "reported an error"
	}
	info = fmt.Sprintf("%s: %s %d of %d probes", msg.Family, batchVerb(msg.Attach, true), done, result.Total)
	if len(result.Errors) == 0 {
		return info, ""
	}
	first := result.Errors[0]
	errText = fmt.Sprintf("%d %s, first %s: %v", len(result.Errors), failure, first.Syscall, first.Err)
	return info, errText
}

// batchVerb names a family batch operation for progress and result lines.
func batchVerb(attach, done bool) string {
	switch {
	case attach && done:
		return "attached"
	case attach:
		return "attaching"
	case done:
		return "detached"
	default:
		return "detaching"
	}
}

// batchLine returns the progress line of the running family batch, or "".
func (m Model) batchLine() string {
	if !m.batch.active {
		return ""
	}
	return fmt.Sprintf("%s %s... %d/%d", batchVerb(m.batch.attach, false), m.batch.family, m.batch.completed, m.batch.total)
}

// renderFamilyRow formats one Families view row: selection prefix, a
// checkbox that is [x] when every probe of the family is attached, [~] when
// some are and [ ] when none are, the family name and attached/total counts.
func renderFamilyRow(state probemanager.FamilyState, selected bool) string {
	prefix := "  "
	if selected {
		prefix = "> "
	}
	check := "[ ]"
	switch {
	case state.Total > 0 && state.Active == state.Total:
		check = "[x]"
	case state.Active > 0:
		check = "[~]"
	}
	return fmt.Sprintf("%s%s %-10s %4d/%-4d", prefix, check, state.Family, state.Active, state.Total)
}
