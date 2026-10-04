package dashboard

import (
	"slices"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/statsengine"
	"ior/internal/tui/common"
	"ior/internal/tui/messages"
	"ior/internal/types"
)

// These tests drive the Processes selection across the auto-reset with the
// real statsengine.Engine: the selection key is the process ID ("8#1" for the
// second process to hold PID 8), so it only survives a reset when the engine
// keeps process identity stable across Engine.Reset. A fake source cannot
// show that, because the identity lives in the engine (task zq2 review).

// enginePair is a read syscall of process pid, enough for the process rows.
func enginePair(pid uint32, comm string) *event.Pair {
	return &event.Pair{
		EnterEv:  &types.RetEvent{TraceId: types.SYS_ENTER_READ, Pid: pid, Tid: pid},
		ExitEv:   &types.RetEvent{TraceId: types.SYS_ENTER_READ, Pid: pid, Tid: pid, RetType: types.READ_CLASSIFIED},
		Comm:     comm,
		Duration: 10,
		Bytes:    4,
		File:     file.NewFd(3, "/tmp/a", -1),
	}
}

// ingestProcesses feeds pids 1..n with counts that descend with the PID, so
// the metric order is the reverse of the PID order the table is sorted by.
func ingestProcesses(e *statsengine.Engine, n uint32) {
	for pid := uint32(1); pid <= n; pid++ {
		for range n + 1 - pid {
			e.Ingest(enginePair(pid, "p"))
		}
	}
}

// newEngineProcessesModel returns a Processes dashboard on a real engine that
// already ran the scenario: 12 processes and a recycled PID 8 (rows 8 and
// 8#1), the second lifetime still running.
func newEngineProcessesModel(t *testing.T, mode tabVizMode) (*Model, *statsengine.Engine) {
	t.Helper()
	e := statsengine.NewEngine(statsengine.DefaultTopN)
	ingestProcesses(e, 12)
	e.RetireProcess(8)
	e.Ingest(enginePair(8, "second"))

	m := NewModelWithConfig(e, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	m.setTabVizMode(TabProcesses, mode)
	m.width, m.height = 120, 28
	if mode == tabVizModeTable {
		m.processesTab.sort = tableSortState[processSortKey]{active: true, key: processSortKeyPID}
	}
	return tickStats(t, m, m.statsTick()), e
}

// selectProcess moves the selection with j until key is selected.
func selectProcess(t *testing.T, m *Model, sel func() keyedSelection, key string) *Model {
	t.Helper()
	for range 30 {
		if sel().selectedKey() == key {
			return m
		}
		m = pressJ(t, m, 1)
	}
	t.Fatalf("could not select %q, at %q of %v", key, sel().selectedKey(), sel().keys())
	return m
}

// applyAutoReset applies the reset the way handleAutoResetTick does: the engine is
// reset and the post-reset (empty) snapshot arrives as the tick of the new
// generation.
func applyAutoReset(t *testing.T, m *Model) *Model {
	t.Helper()
	msg, ok := m.resetBaselineCmd()().(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("resetBaselineCmd did not yield a stats tick")
	}
	m = tickStats(t, m, msg)
	if got := len(m.latest.Processes()); got != 0 {
		t.Fatalf("precondition: %d process rows right after the reset", got)
	}
	return m
}

// TestProcessesSelectionOfRecycledPIDSurvivesEngineReset is the review
// repro: the selected row is the running second process of PID 8 ("8#1").
// After the reset that same process reappears, and it must be selected again
// - in the table and in the treemap, with a refill in another order.
func TestProcessesSelectionOfRecycledPIDSurvivesEngineReset(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode tabVizMode
		sel  func(m *Model) func() keyedSelection
	}{
		{"table", tabVizModeTable, func(m *Model) func() keyedSelection { return m.processesTableSelection }},
		{"treemap", tabVizModeTreemap, func(m *Model) func() keyedSelection { return m.processesTreemapSelection }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeStickyClock(t)
			m, e := newEngineProcessesModel(t, tc.mode)
			m = selectProcess(t, m, tc.sel(m), processKey(8, 1))

			m = applyAutoReset(t, m)
			// Every process is back, the metric order differs from the pre-reset
			// one (8#1 issues the most calls now), and PID 8 is lifetime 1 again.
			ingestProcesses(e, 12)
			for range 30 {
				e.Ingest(enginePair(8, "second"))
			}
			m = tickStats(t, m, m.statsTick())
			m = tickStats(t, m, m.statsTick())
			if got := tc.sel(m)().selectedKey(); got != processKey(8, 1) {
				t.Fatalf("selected %q after the reset, want %q (rows %v)", got, processKey(8, 1), tc.sel(m)().keys())
			}
			if row, ok := m.selectedProcessSnapshot(); !ok || row.PID != 8 || row.Lifetime != 1 {
				t.Fatalf("Enter targets %+v (ok=%v), want PID 8 lifetime 1", row, ok)
			}
		})
	}
}

// TestProcessesSelectionIsNotStolenByAnotherProcessOfTheSamePID: the selected
// process 8#1 exits right after the reset (before it issued another call), and
// two later processes are handed PID 8. Neither may be selected in its place,
// whatever ordinal it gets: the wish is for the process that died.
func TestProcessesSelectionIsNotStolenByAnotherProcessOfTheSamePID(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode tabVizMode
		sel  func(m *Model) func() keyedSelection
	}{
		{"table", tabVizModeTable, func(m *Model) func() keyedSelection { return m.processesTableSelection }},
		{"treemap", tabVizModeTreemap, func(m *Model) func() keyedSelection { return m.processesTreemapSelection }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeStickyClock(t)
			m, e := newEngineProcessesModel(t, tc.mode)
			m = selectProcess(t, m, tc.sel(m), processKey(8, 1))

			m = applyAutoReset(t, m)
			e.RetireProcess(8) // 8#1 exits; its row never reopens
			ingestProcesses(e, 12)
			e.RetireProcess(8)
			e.Ingest(enginePair(8, "stranger")) // another process now holds PID 8
			m = tickStats(t, m, m.statsTick())
			m = tickStats(t, m, m.statsTick())

			// The cursor may sit on a row of PID 8 by position (the clamped
			// placeholder), so the guard is the ID: nothing may carry 8#1 and
			// so nothing can satisfy the wish for the dead process.
			keys := tc.sel(m)().keys()
			for _, k := range keys {
				if k == processKey(8, 1) {
					t.Fatalf("a process took the ID of the exited 8#1: %v", keys)
				}
			}
			if got := tc.sel(m)().selectedKey(); got == processKey(8, 1) {
				t.Fatalf("selection follows %q to another process (rows %v)", got, keys)
			}
			if !slices.Contains(keys, processKey(8, 3)) {
				t.Fatalf("precondition: the stranger is not listed as 8#3: %v", keys)
			}
		})
	}
}
