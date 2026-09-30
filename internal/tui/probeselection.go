package tui

import (
	"errors"

	"ior/internal/probemanager"
	"ior/internal/tui/probes"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// familyRunState is the family batch the model owns. Only one runs at a
// time; seq numbers the runs so messages of any other run are ignored, and
// session is the trace session whose probe manager the batch works on.
type familyRunState struct {
	seq     uint64
	active  bool
	session uint64
	// family and attach are what the run changes; while it runs, any other
	// probe change records its intended outcome on top (rememberProbeSelection).
	family types.SyscallFamily
	attach bool
	// last is the latest progress, replayed into a rebuilt probes modal.
	last probes.FamilyBatchProgressMsg
}

// staleBatchNote is appended to a family batch's outcome when the trace was
// restarted or stopped while the batch ran on the old session's manager: the
// intended set is kept for the next session (the current one, after a
// restart, already started with it).
const staleBatchNote = "(trace restarted or stopped meanwhile; the intended probe set is kept for the next session)"

// newProbeModal builds the probes modal for the current probe manager. Its
// Families cursor starts on the dashboard's scoped family, so the family
// hint's "o, tab, space" acts on that family, and a family batch still in
// flight is shown right away rather than only at its next progress update.
func (m *Model) newProbeModal() probes.Model {
	modal := probes.NewModel(m.runtime.currentProbeManager()).
		WithSession(m.tracer.session).
		SetDarkMode(m.isDark).
		FocusFamily(scopedFamily(m.filters.current()))
	if m.familyRun.active {
		modal = modal.ShowBatchProgress(m.familyRun.last)
	}
	return modal
}

// startFamilyBatch starts the family attach/detach the probes modal asked
// for, unless one is already running.
//
// Before the batch starts, the probe set it is meant to produce is recorded
// as the selection for the next trace sessions. A restart can then happen at
// any point during the batch - which keeps working on the old session's
// manager - and the new session still attaches what the user asked for;
// completion replaces the intent with the read-back truth only while the
// batch's session is still current (handleFamilyToggledMsg).
func (m *Model) startFamilyBatch(req probes.FamilyBatchRequestMsg) tea.Cmd {
	if m.familyRun.active {
		m.probeModal = m.probeModal.ShowBatchProgress(m.familyRun.last).
			SetError("a family batch is already running")
		return nil
	}
	manager := m.runtime.currentProbeManager()
	if manager == nil {
		failed := probes.FamilyToggledMsg{Family: req.Family, Attach: req.Attach, Err: errors.New("probe manager unavailable")}
		m.probeModal = m.probeModal.FinishBatch(failed, "")
		return nil
	}
	states := manager.States()
	m.tracer.setAttachSyscalls(intendedSelection(states, req.Family, req.Attach))
	m.familyRun.seq++
	m.familyRun.active = true
	m.familyRun.session = m.tracer.session
	m.familyRun.family = req.Family
	m.familyRun.attach = req.Attach
	m.familyRun.last = probes.FamilyBatchProgressMsg{
		Run: m.familyRun.seq, Family: req.Family, Attach: req.Attach, Total: batchSize(states, req.Family, req.Attach),
	}
	return probes.StartFamilyBatch(manager, m.familyRun.seq, req.Family, req.Attach)
}

// handleFamilyBatchProgress shows the owned batch's progress and keeps
// following it; the probes modal may be closed or rebuilt meanwhile.
func (m *Model) handleFamilyBatchProgress(msg probes.FamilyBatchProgressMsg) tea.Cmd {
	if !m.familyRun.owns(msg.Run) {
		return nil
	}
	m.familyRun.last = msg
	m.probeModal = m.probeModal.ShowBatchProgress(msg)
	return msg.Next()
}

// handleFamilyToggledMsg ends the owned family batch. While its session is
// still the current one, the model reacts like to any probe change
// (afterProbeChange reads the attached set back from the manager). If the
// trace was restarted or stopped meanwhile, the batch changed a manager that
// is gone: the intent recorded at start stays the selection (the new session
// already attached it) and the outcome says so.
func (m *Model) handleFamilyToggledMsg(msg probes.FamilyToggledMsg) (tea.Model, tea.Cmd) {
	if !m.familyRun.owns(msg.Run) {
		return m, nil
	}
	m.familyRun.active = false
	if !m.tracer.isCurrent(m.familyRun.session) {
		m.probeModal = m.probeModal.FinishBatch(msg, staleBatchNote)
		m.refreshFamilyHint()
		return m, nil
	}
	m.probeModal = m.probeModal.FinishBatch(msg, "")
	return m, m.afterProbeChange()
}

// owns reports whether run is the batch in flight.
func (r familyRunState) owns(run uint64) bool {
	return r.active && run == r.seq
}

// intendedSelection returns the attached set a family batch is meant to
// leave behind: the currently active syscalls with every syscall of family
// added (attach) or removed (detach). Non-nil, like activeSyscalls.
func intendedSelection(states []probemanager.ProbeState, family types.SyscallFamily, attach bool) []string {
	out := make([]string, 0, len(states))
	for _, state := range states {
		active := state.Active
		if probemanager.SyscallFamily(state.Syscall) == family {
			active = attach
		}
		if active {
			out = append(out, state.Syscall)
		}
	}
	return out
}

// batchSize returns how many probes a family batch has to change: the
// family's detached probes for an attach, its attached ones for a detach.
func batchSize(states []probemanager.ProbeState, family types.SyscallFamily, attach bool) int {
	n := 0
	for _, state := range states {
		if state.Active != attach && probemanager.SyscallFamily(state.Syscall) == family {
			n++
		}
	}
	return n
}

// afterProbeChange is the model's reaction to any runtime probe change
// (single toggle, all-on/all-off, family batch): it remembers the attached
// set for the next trace restart, refreshes the family "not traced" hint,
// and resets the dashboard aggregates so the new probe set shows at once.
func (m *Model) afterProbeChange() tea.Cmd {
	m.rememberProbeSelection()
	m.refreshFamilyHint()
	return m.dashboard.ResetStats()
}

// handleProbeToggledMsg handles the end of a single or bulk toggle. While
// the toggle's session is current, the model reacts like to any probe change
// (afterProbeChange). A result that arrives after a restart or stop toggled a
// manager that is gone: reading back the new session's manager would record
// that session's state rather than the toggle, so the toggle's intent becomes
// the selection for the next session instead. Either way the dashboard
// aggregates are reset; the post-reset tick goes through the dashboard's
// normal stats handling, so a failed snapshot keeps the last good one.
func (m *Model) handleProbeToggledMsg(msg probes.ProbeToggledMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.probeModal, cmd = m.probeModal.Update(msg)
	if m.tracer.isCurrent(msg.Session) {
		return m, tea.Batch(m.afterProbeChange(), cmd)
	}
	if msg.Intent != nil {
		m.tracer.setAttachSyscalls(msg.Intent)
	}
	m.refreshFamilyHint()
	return m, tea.Batch(m.dashboard.ResetStats(), cmd)
}

// rememberProbeSelection records the probe set the next trace sessions
// attach, so a restart (PID/TID reselect, a filter change that cannot be
// swapped live) keeps what the user attached or detached instead of
// reverting to the startup -trace-* selection.
//
// Normally it reads the attached set back from the live manager: that is the
// truth after partial failures (a probe whose tracepoint is missing stays
// detached and is not carried over). While a family batch of the current
// session is still running, the read-back is half done, so the batch's
// intended outcome is applied on top of it (intendedSelection) - otherwise a
// single toggle finishing mid-batch would drop the rest of the family from
// the selection. With no manager published the previous selection is kept.
//
// The selection is an intent, not always a read-back: a batch or toggle that
// finished after its session ended records what it was meant to do. Probes of
// such an intent that cannot attach are retried at each session start and
// skipped (logged) until the next probe change reads the truth back.
func (m *Model) rememberProbeSelection() {
	manager := m.runtime.currentProbeManager()
	if manager == nil {
		return
	}
	states := manager.States()
	if m.familyRun.active && m.tracer.isCurrent(m.familyRun.session) {
		m.tracer.setAttachSyscalls(intendedSelection(states, m.familyRun.family, m.familyRun.attach))
		return
	}
	m.tracer.setAttachSyscalls(activeSyscalls(states))
}

// activeSyscalls returns the syscalls of the active probes in states. The
// result is non-nil even when nothing is active: an empty selection means
// "attach nothing", not "use the startup selection".
func activeSyscalls(states []probemanager.ProbeState) []string {
	out := make([]string, 0, len(states))
	for _, state := range states {
		if state.Active {
			out = append(out, state.Syscall)
		}
	}
	return out
}

// refreshFamilyHint shows, in the dashboard's filter notice, a hint when the
// dashboard is scoped to a syscall family none of whose probes is attached -
// e.g. after cycling onto Network with '['/']' when only FS is traced, which
// would otherwise just show empty tabs. It clears its own hint once the scope
// changes or the family gets attached, but never a filter-refusal notice
// (familyHintShown). Without a published probe manager (still attaching,
// test-flames mode) the attach state is unknown and nothing is shown.
func (m *Model) refreshFamilyHint() {
	hint := ""
	if manager := m.runtime.currentProbeManager(); manager != nil {
		hint = probes.NotTracedHint(scopedFamily(m.filters.current()), manager.States())
	}
	if hint != "" {
		m.dashboard.SetFilterNotice(hint)
		m.familyHintShown = true
		return
	}
	if m.familyHintShown {
		m.setFilterNotice("")
	}
}

// setFilterNotice writes the dashboard's filter notice for a filter change
// (refusal reason or ""), which replaces any family hint showing.
func (m *Model) setFilterNotice(notice string) {
	m.dashboard.SetFilterNotice(notice)
	m.familyHintShown = false
}
