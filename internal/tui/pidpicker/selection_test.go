package pidpicker

import (
	"testing"

	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// loadedModel returns a picker fed the given scan through Update, the way the
// real program delivers a scan result.
func loadedModel(t *testing.T, m Model, procs ...ProcessInfo) Model {
	t.Helper()
	next, _ := m.Update(processesLoadedMsg{processes: procs})
	return next.(Model)
}

// pressDown moves the highlight down n rows through the real key path.
func pressDown(t *testing.T, m Model, n int) Model {
	t.Helper()
	for i := 0; i < n; i++ {
		next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
		m = next.(Model)
	}
	return m
}

// enterMsg presses Enter and returns the emitted message.
func enterMsg(t *testing.T, m Model) tea.Msg {
	t.Helper()
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		t.Fatalf("enter returned no command")
	}
	return cmd()
}

// TestRefreshKeepsSelectedPidWhenRowsShift is the task 6r2 regression: pid 30
// is selected, pid 10 exits and the rescan puts a new pid 40 last. Keeping the
// row index would move the highlight (and Enter) to pid 40.
func TestRefreshKeepsSelectedPidWhenRowsShift(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()),
		ProcessInfo{Pid: 10, Comm: "a"}, ProcessInfo{Pid: 20, Comm: "b"}, ProcessInfo{Pid: 30, Comm: "c"})
	m = pressDown(t, m, 3) // All, 10, 20, 30 -> row 3 is pid 30
	if got := m.selectedIndex; got != 3 {
		t.Fatalf("setup: selectedIndex = %d, want 3", got)
	}

	// 'r' rescans once the input is blurred by Down; deliver the scan result.
	m = loadedModel(t, m,
		ProcessInfo{Pid: 20, Comm: "b"}, ProcessInfo{Pid: 30, Comm: "c"}, ProcessInfo{Pid: 40, Comm: "d"})

	if got := m.selectedIndex; got != 2 {
		t.Fatalf("selectedIndex = %d, want 2 (pid 30 moved up one row)", got)
	}
	msg, ok := enterMsg(t, m).(messages.PidSelectedMsg)
	if !ok || msg.Pid != 30 {
		t.Fatalf("Enter emitted %+v, want PidSelectedMsg{Pid: 30}", msg)
	}
}

// TestRefreshFallsBackToAllRowWhenSelectedPidExited is the negative case: the
// selected process is gone, so the selection must not slide onto a neighbour.
func TestRefreshFallsBackToAllRowWhenSelectedPidExited(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()),
		ProcessInfo{Pid: 10}, ProcessInfo{Pid: 20}, ProcessInfo{Pid: 30})
	m = pressDown(t, m, 2) // pid 20

	m = loadedModel(t, m, ProcessInfo{Pid: 10}, ProcessInfo{Pid: 30}, ProcessInfo{Pid: 40})

	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want 0 (All row) after the selected pid exited", m.selectedIndex)
	}
	msg, ok := enterMsg(t, m).(messages.PidSelectedMsg)
	if !ok || msg.Pid != 0 {
		t.Fatalf("Enter emitted %+v, want PidSelectedMsg{Pid: 0}, never a neighbouring pid", msg)
	}
}

// TestRefreshKeepsAllRowSelected: the All row has no pid identity and stays.
func TestRefreshKeepsAllRowSelected(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()), ProcessInfo{Pid: 10}, ProcessInfo{Pid: 20})
	m = loadedModel(t, m, ProcessInfo{Pid: 5}, ProcessInfo{Pid: 10})
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want 0", m.selectedIndex)
	}
}

// TestRefreshEmptyScanResetsToAllRow: an empty scan must not leave an
// out-of-range selection behind.
func TestRefreshEmptyScanResetsToAllRow(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()), ProcessInfo{Pid: 10})
	m = pressDown(t, m, 1)
	m = loadedModel(t, m)
	if m.selectedIndex != 0 || len(m.filtered) != 0 {
		t.Fatalf("selectedIndex=%d filtered=%d, want 0 and 0", m.selectedIndex, len(m.filtered))
	}
}

// TestRefreshKeepsSelectedTidInTIDMode: in TID mode the identity is the tid
// (ProcessInfo.Pid), also when the same rescan reorders other threads.
func TestRefreshKeepsSelectedTidInTIDMode(t *testing.T) {
	m := loadedModel(t, NewTIDWithKeys(0, DefaultKeyMap()),
		ProcessInfo{Pid: 101, ParentPID: 100}, ProcessInfo{Pid: 102, ParentPID: 100}, ProcessInfo{Pid: 201, ParentPID: 200})
	m = pressDown(t, m, 3) // tid 201

	m = loadedModel(t, m,
		ProcessInfo{Pid: 300, ParentPID: 3}, ProcessInfo{Pid: 102, ParentPID: 100}, ProcessInfo{Pid: 201, ParentPID: 200})

	msg, ok := enterMsg(t, m).(messages.TidSelectedMsg)
	if !ok || msg.Pid != 200 || msg.Tid != 201 {
		t.Fatalf("Enter emitted %+v, want TidSelectedMsg{Pid: 200, Tid: 201}", msg)
	}
}

// TestFilterChangeKeepsSelectedPid: typing in the filter reshapes the list the
// same way a rescan does; the highlighted process must stay highlighted while
// it still matches and fall back to All once it does not.
func TestFilterChangeKeepsSelectedPid(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()),
		ProcessInfo{Pid: 10, Comm: "alpha"}, ProcessInfo{Pid: 20, Comm: "beta"}, ProcessInfo{Pid: 30, Comm: "beta2"})
	m = pressDown(t, m, 3) // pid 30

	next, _ := m.Update(tea.KeyPressMsg{Code: 'b', Text: "b"})
	m = next.(Model)
	if msg, ok := enterMsg(t, m).(messages.PidSelectedMsg); !ok || msg.Pid != 30 {
		t.Fatalf("after filtering to b*, Enter emitted %+v, want pid 30", msg)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: 'x', Text: "x"}) // "bx" matches nothing
	m = next.(Model)
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want 0 once the selected pid no longer matches", m.selectedIndex)
	}
}
