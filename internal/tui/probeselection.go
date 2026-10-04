package tui

import (
	"context"
	"errors"
	"slices"

	"ior/internal/probemanager"
	"ior/internal/tui/probes"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// familyRunState is the family batch the model owns. seq numbers the runs so
// messages of any other run are ignored, and session is the trace session
// whose probe manager the batch works on.
//
// active means the run's result is still awaited. Only a run of the current
// session blocks anything (Model.familyBatchRunning): one at a time, and no
// Syscalls-view change meanwhile. Ending the session cancels the batch (it
// runs on the session's context) and releases that block at once, without
// waiting for the stale result, so the next session can start a family batch
// right away; a newer run then takes over seq and the stale result is
// ignored when it arrives.
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

// bulkRunState is the all-on/all-off walk (the modal's a / n keys) the model
// owns, in the trace session it runs in. Like a family batch it is requested
// by the modal and run by the model on the session's context
// (startSetAll); one runs at a time per session, and it blocks family batches
// and further a/n meanwhile.
//
// intent is the probe set the walk is meant to produce, recorded as the
// selection when the key is pressed. While the walk runs, the live manager is
// half done, so anything that would read the selection back from it applies
// intent instead (rememberProbeSelection).
type bulkRunState struct {
	active  bool
	session uint64
	intent  []string
}

// Refusal notices for probe changes that would race a running walk or batch.
const (
	bulkBusyNotice        = probes.BulkBusyNotice
	batchRunningNotice    = "a family batch is already running"
	errProbeManagerAbsent = "probe manager unavailable"
)

// staleBatchNote and cancelledBatchNote are appended to a family batch's
// outcome when the trace was restarted or stopped while the batch ran on the
// old session's manager: the intended set is kept for the next session (the
// current one, after a restart, already started with it). Ending the session
// cancels the batch, but one that had already visited every probe finishes
// uncancelled, so only a batch that reports the cancellation says so.
const (
	staleBatchNote     = "(trace restarted or stopped meanwhile; the intended probe set is kept for the next session)"
	cancelledBatchNote = "(trace restarted or stopped meanwhile, batch cancelled; the intended probe set is kept for the next session)"
)

// familyBatchRunning reports whether a family batch of the current trace
// session is in flight. A batch of an ended session no longer counts: it was
// cancelled with its session and must not hold up the next one.
func (m *Model) familyBatchRunning() bool {
	return m.familyRun.active && m.tracer.isCurrent(m.familyRun.session)
}

// bulkRunning reports whether an all-on/all-off walk of the current trace
// session is in flight; one of an ended session no longer counts.
func (m *Model) bulkRunning() bool {
	return m.bulkRun.active && m.tracer.isCurrent(m.bulkRun.session)
}

// newProbeModal builds the probes modal for the current probe manager. Its
// Families cursor starts on the dashboard's scoped family, so the family
// hint's "O, tab, space" acts on that family, and a family batch or an
// all-on/all-off walk still in flight is shown (and its guard armed) right
// away rather than only at its next progress update.
func (m *Model) newProbeModal() probes.Model {
	modal := probes.NewModel(m.runtime.currentProbeManager()).
		WithSession(m.tracer.session).
		SetDarkMode(m.isDark).
		FocusFamily(scopedFamily(m.filters.current()))
	if m.familyBatchRunning() {
		modal = modal.ShowBatchProgress(m.familyRun.last)
	}
	return modal.SetBulkRunning(m.bulkRunning())
}

// rebindProbeModal points an open probes modal at the current trace session
// and its probe manager (none while the session is still attaching); a modal
// that is not open is rebuilt by newProbeModal when it opens, so it is left
// alone. The modal keeps its cursor and its info line (a family batch's
// "trace restarted" outcome is shown in it) but drops an error or refusal of
// the old session, and the guard of a walk is re-derived: a walk of an ended
// session no longer blocks anything.
func (m *Model) rebindProbeModal() {
	if !m.probeModal.Visible() {
		return
	}
	m.probeModal = m.probeModal.Rebind(m.runtime.currentProbeManager(), m.tracer.session).
		SetBulkRunning(m.bulkRunning())
}

// startFamilyBatch starts the family attach/detach the probes modal asked
// for, unless one of the current session is already running. The batch runs
// on the session's context, so it stops when the session ends.
//
// Before the batch starts, the probe set it is meant to produce is recorded
// as the selection for the next trace sessions. A restart can then happen at
// any point during the batch - which keeps working on the old session's
// manager - and the new session still attaches what the user asked for;
// completion replaces the intent with the read-back truth only while the
// batch's session is still current (handleFamilyToggledMsg).
func (m *Model) startFamilyBatch(req probes.FamilyBatchRequestMsg) tea.Cmd {
	if m.familyBatchRunning() {
		m.probeModal = m.probeModal.ShowBatchProgress(m.familyRun.last).
			SetError(batchRunningNotice)
		return nil
	}
	if m.bulkRunning() {
		// The manager is half done, so the batch's intent could not be derived.
		m.probeModal = m.probeModal.SetError(bulkBusyNotice)
		return nil
	}
	manager := m.runtime.currentProbeManager()
	if manager == nil {
		failed := probes.FamilyToggledMsg{Family: req.Family, Attach: req.Attach, Err: errors.New(errProbeManagerAbsent)}
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
	return probes.StartFamilyBatch(m.tracer.sessionContext(), manager, m.familyRun.seq, req.Family, req.Attach)
}

// handleFamilyBatchProgress shows the owned batch's progress and keeps
// following it; the probes modal may be closed or rebuilt meanwhile. The
// progress of a batch whose session has ended is not shown - it would make
// the modal refuse changes again - but the batch is still followed to its
// (cancelled) result, which reports the outcome.
func (m *Model) handleFamilyBatchProgress(msg probes.FamilyBatchProgressMsg) tea.Cmd {
	if !m.familyRun.owns(msg.Run) {
		return nil
	}
	if m.familyBatchRunning() {
		m.familyRun.last = msg
		m.probeModal = m.probeModal.ShowBatchProgress(msg)
	}
	return msg.Next()
}

// handleFamilyToggledMsg ends the owned family batch. While its session is
// still the current one, the model reacts like to any probe change
// (afterProbeChange reads the attached set back from the manager). If the
// trace was restarted or stopped meanwhile, the batch was cancelled on a
// manager that is gone: the intent recorded at start stays the selection (the
// new session already attached it) and the outcome says so, reporting the
// probes changed before the cancellation rather than the cancellation as an
// error. A stale result arriving after a newer batch started is not owned any
// more and ignored outright.
func (m *Model) handleFamilyToggledMsg(msg probes.FamilyToggledMsg) (tea.Model, tea.Cmd) {
	if !m.familyRun.owns(msg.Run) {
		return m, nil
	}
	m.familyRun.active = false
	if !m.tracer.isCurrent(m.familyRun.session) {
		note := staleBatchNote
		if errors.Is(msg.Err, context.Canceled) {
			msg.Err, note = nil, cancelledBatchNote
		}
		m.probeModal = m.probeModal.FinishBatch(msg, note)
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

// startSetAll starts the all-on/all-off walk the probes modal asked for, like
// startFamilyBatch: the model, not the modal, owns it so that it belongs to
// the trace session.
//
//   - The intended probe set (every registered syscall, or none) is recorded as
//     the selection for the next sessions when the key is pressed. A restart
//     while the walk runs - it takes seconds and keeps working on the old
//     session's manager - then still starts the next session with what the user
//     asked for, and the walk's late result records nothing.
//   - The walk runs on the session's context (traceLifecycle.sessionContext),
//     so ending the session stops it between two probes instead of attaching
//     to a manager that is about to close, and its result is tagged with the
//     session so a stale one is recognised (handleProbeToggledMsg).
//   - One walk per session at a time, and none while a family batch runs; the
//     refusal is shown in the modal. The modal also refuses single toggles
//     while the walk runs (SetBulkRunning), as they would race it.
func (m *Model) startSetAll(req probes.SetAllRequestMsg) tea.Cmd {
	switch {
	case m.familyBatchRunning():
		m.probeModal = m.probeModal.ShowBatchProgress(m.familyRun.last).SetError(batchRunningNotice)
		return nil
	case m.bulkRunning():
		m.probeModal = m.probeModal.SetError(bulkBusyNotice)
		return nil
	}
	manager := m.runtime.currentProbeManager()
	if manager == nil {
		m.probeModal = m.probeModal.SetError(errProbeManagerAbsent)
		return nil
	}
	intent := allSelection(manager.States(), req.Active)
	m.tracer.setAttachSyscalls(slices.Clone(intent))
	m.bulkRun = bulkRunState{active: true, session: m.tracer.session, intent: intent}
	m.probeModal = m.probeModal.SetBulkRunning(true)
	return probes.SetAllCmd(m.tracer.sessionContext(), manager, req.Active, m.tracer.session)
}

// allSelection returns the attached set an all-on (active) or all-off walk is
// meant to leave behind: every registered syscall, or none. Non-nil, like
// activeSyscalls.
func allSelection(states []probemanager.ProbeState, active bool) []string {
	out := make([]string, 0, len(states))
	if active {
		for _, state := range states {
			out = append(out, state.Syscall)
		}
	}
	return out
}

// handleProbeToggledMsg handles the end of a single or bulk toggle. While
// the toggle's session is current, the modal shows the outcome and the model
// reacts like to any probe change (afterProbeChange).
//
// A result that arrives after a restart or stop toggled a manager that is
// gone, and is dropped as far as the screen goes: it is not shown in the
// modal (its error, typically "probe manager is closed", describes a dead
// manager and would show up in the new session's modal). Reading back the new
// session's manager would record that session's state rather than the toggle,
// so a single toggle's intent is applied to the recorded selection instead
// (applyStaleToggle); an all-on/all-off walk recorded its intent at the key
// press already. The result of the running walk (and only of that one: a stale
// result of an earlier session must not release the running walk's guard)
// ends it and lifts the modal's refusal of single toggles. Either way the
// dashboard aggregates are reset; the post-reset tick goes through the
// dashboard's normal stats handling, so a failed snapshot keeps the last good
// one.
func (m *Model) handleProbeToggledMsg(msg probes.ProbeToggledMsg) (tea.Model, tea.Cmd) {
	if msg.Syscall == "" && m.bulkRun.active && msg.Session == m.bulkRun.session {
		// Only the walk's own result ends it: a stale result of an earlier
		// session must not release the guard of the walk running now.
		m.bulkRun.active = false
		m.probeModal = m.probeModal.SetBulkRunning(false)
	}
	if !m.tracer.isCurrent(msg.Session) {
		m.applyStaleToggle(msg)
		m.refreshFamilyHint()
		return m, m.dashboard.ResetStats()
	}
	var cmd tea.Cmd
	m.probeModal, cmd = m.probeModal.Update(msg)
	return m, tea.Batch(m.afterProbeChange(), cmd)
}

// applyStaleToggle records the intent of a single toggle whose session has
// ended. It changes one probe, so only that delta is applied to the recorded
// selection - replacing the whole selection with the toggle's absolute intent
// (a snapshot of the old manager) would clobber anything recorded since, such
// as a family batch's or all-on/all-off's intent. The exception is nothing
// recorded yet (nil: the startup selection, which has no explicit set to
// apply a delta to), where the intent is recorded as is. A result without
// Syscall is an all-on/all-off walk: its intent was recorded when it started,
// and a late result must not replay it over newer changes.
func (m *Model) applyStaleToggle(msg probes.ProbeToggledMsg) {
	if msg.Intent == nil || msg.Syscall == "" {
		return // the toggle never ran, or a bulk walk that recorded at start
	}
	selection := m.tracer.attachSyscalls
	if selection == nil {
		m.tracer.setAttachSyscalls(msg.Intent)
		return
	}
	selection = slices.DeleteFunc(slices.Clone(selection), func(s string) bool { return s == msg.Syscall })
	if slices.Contains(msg.Intent, msg.Syscall) {
		selection = append(selection, msg.Syscall)
		slices.Sort(selection)
	}
	m.tracer.setAttachSyscalls(selection)
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
// intended outcome is applied on top of it (intendedSelection); likewise an
// all-on/all-off walk in flight makes the selection its intent (bulkRun). The
// modal refuses probe changes while a batch runs, so this only matters for a
// single toggle already in flight when the batch or walk started, which would
// otherwise record the half-done state and drop the rest of the family or of
// the walk from the selection. With no manager published the previous
// selection is kept.
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
	if m.familyBatchRunning() {
		m.tracer.setAttachSyscalls(intendedSelection(states, m.familyRun.family, m.familyRun.attach))
		return
	}
	if m.bulkRunning() {
		m.tracer.setAttachSyscalls(slices.Clone(m.bulkRun.intent))
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

// refreshFamilyHint shows a hint in the dashboard chrome when the dashboard
// is scoped to a syscall family none of whose probes is attached - e.g. after
// cycling onto Network with '['/']' when only FS is traced, which would
// otherwise just show empty tabs - and clears it otherwise. The hint is
// derived from the current filter and probe states alone, so it is refreshed
// on every filter change on screen (syncDashboardFilterState) and every probe
// change. It lives in its own dashboard slot (SetFamilyHint), apart from the
// filter notice, so a refresh can never replace or clear a FILTER REFUSED
// notice. Without a published probe manager (still attaching, test-flames
// mode) the attach state is unknown and nothing is shown.
func (m *Model) refreshFamilyHint() {
	hint := ""
	if manager := m.runtime.currentProbeManager(); manager != nil {
		hint = probes.NotTracedHint(scopedFamily(m.filters.current()), manager.States())
	}
	m.dashboard.SetFamilyHint(hint)
}
