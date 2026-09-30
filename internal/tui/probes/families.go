package probes

import (
	"fmt"

	"ior/internal/probemanager"
	common "ior/internal/tui/common"
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
// empty with no explanation. It returns "" when family is empty (unscoped) or
// has at least one active probe.
func NotTracedHint(family string, states []probemanager.ProbeState) string {
	if family == "" {
		return ""
	}
	for _, state := range probemanager.FamilyStates(states) {
		if string(state.Family) == family && state.Active > 0 {
			return ""
		}
	}
	return family + " not traced: press o, tab, space to attach"
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

// toggleSelectedFamily starts detaching the selected family when any of its
// probes is attached and attaching it otherwise. Only one family batch runs
// at a time; a key press while one runs is ignored (its progress is shown).
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
	m.batch = familyBatch{active: true, family: state.Family, attach: attach, total: state.Total}
	m.lastErr = ""
	m.lastInfo = ""
	return m.clampCursor(), familyBatchCmd(m.manager, state.Family, attach)
}

// handleBatchProgress records a family batch's progress and keeps waiting.
func (m Model) handleBatchProgress(msg FamilyBatchProgressMsg) (Model, tea.Cmd) {
	m.batch = familyBatch{active: true, family: msg.Family, attach: msg.Attach, completed: msg.Completed, total: msg.Total}
	return m.clampCursor(), msg.waitCmd()
}

// handleFamilyToggled ends a family batch: it reloads the probe list and
// reports how many probes changed and, if any failed, the first failure.
// The failing probes also carry their error in the Syscalls view rows.
func (m Model) handleFamilyToggled(msg FamilyToggledMsg) (Model, tea.Cmd) {
	m.batch = familyBatch{}
	m = m.reload()
	m.lastInfo, m.lastErr = familyOutcome(msg)
	return m.clampCursor(), nil
}

// familyOutcome returns the info and error text for a finished family batch.
func familyOutcome(msg FamilyToggledMsg) (info, errText string) {
	if msg.Err != nil {
		return "", fmt.Sprintf("%s: %v", msg.Family, msg.Err)
	}
	result := msg.Result
	info = fmt.Sprintf("%s: %s %d of %d probes", msg.Family, batchVerb(msg.Attach, true), result.Changed, result.Total)
	if len(result.Errors) == 0 {
		return info, ""
	}
	first := result.Errors[0]
	errText = fmt.Sprintf("%d failed, first %s: %v", len(result.Errors), first.Syscall, first.Err)
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

// familyRows renders the l.rows-high window of the Families view.
func (m Model) familyRows(l probeLayout) []string {
	families := m.familyStates()
	start := min(m.famOffset, len(families))
	end := min(start+l.rows, len(families))
	width := contentWidth(l.box)
	rows := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		row := renderFamilyRow(families[i], i == m.famCursor)
		rows = append(rows, common.TruncateRight(row, width, common.ASCIIEllipsis))
	}
	return rows
}
