package tui

import (
	"ior/internal/probemanager"
	"ior/internal/tui/probes"

	tea "charm.land/bubbletea/v2"
)

// handleFamilyToggledMsg ends a family attach/detach started in the probes
// modal: the modal reports the outcome (it follows the batch even while
// hidden) and the model reacts to the probe change like to a single toggle.
func (m *Model) handleFamilyToggledMsg(msg probes.FamilyToggledMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.probeModal, cmd = m.probeModal.Update(msg)
	return m, tea.Batch(m.afterProbeChange(), cmd)
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

// rememberProbeSelection records the currently attached syscalls as the probe
// set the next trace sessions attach, so a restart (PID/TID reselect, a filter
// change that cannot be swapped live) keeps what the user attached or
// detached instead of reverting to the startup -trace-* selection.
//
// It reads the attached set back from the live manager rather than tracking
// the requested changes: that is the truth after partial failures (a probe
// whose tracepoint is missing stays detached and is not carried over). With
// no manager published - the change raced a restart, and the manager it hit
// is gone - the previous selection is kept.
func (m *Model) rememberProbeSelection() {
	manager := m.runtime.currentProbeManager()
	if manager == nil {
		return
	}
	m.tracer.setAttachSyscalls(activeSyscalls(manager.States()))
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
