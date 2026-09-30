package pidpicker

import (
	"strings"
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

// enterCmd presses Enter and returns the command, which is nil for a no-op.
func enterCmd(m Model) tea.Cmd {
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	return cmd
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

// TestRefreshLosesSelectionWhenSelectedPidExited is the negative case: the
// selected process is gone, so the selection must neither slide onto a
// neighbour nor fall onto the All row, whose Enter traces the whole system.
func TestRefreshLosesSelectionWhenSelectedPidExited(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()),
		ProcessInfo{Pid: 10}, ProcessInfo{Pid: 20}, ProcessInfo{Pid: 30})
	m = pressDown(t, m, 2) // pid 20

	m = loadedModel(t, m, ProcessInfo{Pid: 10}, ProcessInfo{Pid: 30}, ProcessInfo{Pid: 40})

	if m.selectedIndex != noSelection {
		t.Fatalf("selectedIndex = %d, want noSelection after the selected pid exited", m.selectedIndex)
	}
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v, want a no-op while the selection is lost", cmd())
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
// out-of-range selection behind. Without a selected process it is just a clamp.
func TestRefreshEmptyScanResetsToAllRow(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()), ProcessInfo{Pid: 10})
	m = loadedModel(t, m)
	if m.selectedIndex != 0 || len(m.filtered) != 0 {
		t.Fatalf("selectedIndex=%d filtered=%d, want 0 and 0", m.selectedIndex, len(m.filtered))
	}
}

// TestRefreshEmptyScanAfterSelectionLosesIt: the same empty scan with a
// process selected means that process is gone.
func TestRefreshEmptyScanAfterSelectionLosesIt(t *testing.T) {
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()), ProcessInfo{Pid: 10})
	m = pressDown(t, m, 1)
	m = loadedModel(t, m)
	if m.selectedIndex != noSelection || len(m.filtered) != 0 {
		t.Fatalf("selectedIndex=%d filtered=%d, want noSelection and 0", m.selectedIndex, len(m.filtered))
	}
}

// TestRefreshKeepsSelectedTidWhenRowShifts: in TID mode the identity is the
// tid (ProcessInfo.Pid) and the row really changes: a new thread is inserted
// before the selected one. A plain clamp would leave Enter on tid 102 and is
// rejected by this test.
func TestRefreshKeepsSelectedTidWhenRowShifts(t *testing.T) {
	m := loadedModel(t, NewTIDWithKeys(0, DefaultKeyMap()),
		ProcessInfo{Pid: 101, ParentPID: 100}, ProcessInfo{Pid: 102, ParentPID: 100}, ProcessInfo{Pid: 201, ParentPID: 200})
	m = pressDown(t, m, 3) // tid 201, row 3

	m = loadedModel(t, m,
		ProcessInfo{Pid: 50, ParentPID: 5}, ProcessInfo{Pid: 101, ParentPID: 100},
		ProcessInfo{Pid: 102, ParentPID: 100}, ProcessInfo{Pid: 201, ParentPID: 200})

	if m.selectedIndex != 4 {
		t.Fatalf("selectedIndex = %d, want 4 (tid 201 moved down one row)", m.selectedIndex)
	}
	msg, ok := enterMsg(t, m).(messages.TidSelectedMsg)
	if !ok || msg.Pid != 200 || msg.Tid != 201 {
		t.Fatalf("Enter emitted %+v, want TidSelectedMsg{Pid: 200, Tid: 201}", msg)
	}
}

// TestRefreshKeepsSelectedTidAmongSiblings mirrors ScanThreads(pid): every
// row shares one ParentPID, so only the tid identifies the selected thread.
// Tracking ParentPID would relocate to the first row (tid 99) and fail here.
func TestRefreshKeepsSelectedTidAmongSiblings(t *testing.T) {
	m := loadedModel(t, NewTIDWithKeys(100, DefaultKeyMap()),
		ProcessInfo{Pid: 100, ParentPID: 100}, ProcessInfo{Pid: 101, ParentPID: 100}, ProcessInfo{Pid: 102, ParentPID: 100})
	m = pressDown(t, m, 3) // tid 102, row 3

	m = loadedModel(t, m,
		ProcessInfo{Pid: 99, ParentPID: 100}, ProcessInfo{Pid: 100, ParentPID: 100},
		ProcessInfo{Pid: 101, ParentPID: 100}, ProcessInfo{Pid: 102, ParentPID: 100})

	msg, ok := enterMsg(t, m).(messages.TidSelectedMsg)
	if !ok || msg.Pid != 100 || msg.Tid != 102 {
		t.Fatalf("Enter emitted %+v, want TidSelectedMsg{Pid: 100, Tid: 102}", msg)
	}
}

// TestTIDModeFallsBackToAllRowWhenThreadExited: All TIDs stays inside the
// process (handleTidSelected keeps the current pid), so the TID picker keeps
// the plain fallback and Enter there is not suppressed.
func TestTIDModeFallsBackToAllRowWhenThreadExited(t *testing.T) {
	m := loadedModel(t, NewTIDWithKeys(100, DefaultKeyMap()),
		ProcessInfo{Pid: 100, ParentPID: 100}, ProcessInfo{Pid: 101, ParentPID: 100})
	m = pressDown(t, m, 2) // tid 101

	m = loadedModel(t, m, ProcessInfo{Pid: 100, ParentPID: 100})

	if m.selectedIndex != 0 || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want the All TIDs row and no notice", m.selectedIndex, m.notice)
	}
	if msg, ok := enterMsg(t, m).(messages.TidSelectedMsg); !ok || msg.Tid != 0 {
		t.Fatalf("Enter emitted %+v, want TidSelectedMsg{Tid: 0}", msg)
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
	if m.selectedIndex != noSelection {
		t.Fatalf("selectedIndex = %d, want noSelection once the selected pid no longer matches", m.selectedIndex)
	}
	if !strings.Contains(m.notice, "pid 30 no longer matches the filter") {
		t.Fatalf("notice = %q, want the filter wording for pid 30", m.notice)
	}
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v after the filter hid the selection, want a no-op", cmd())
	}
}

// lostModel returns a PID picker with pid 20 selected that then exited.
func lostModel(t *testing.T) Model {
	t.Helper()
	m := loadedModel(t, NewWithKeys(DefaultKeyMap()),
		ProcessInfo{Pid: 10, Comm: "a"}, ProcessInfo{Pid: 20, Comm: "b"}, ProcessInfo{Pid: 30, Comm: "c"})
	m = pressDown(t, m, 2)
	return loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "a"}, ProcessInfo{Pid: 30, Comm: "c"})
}

// TestLostSelectionShowsNoticeAndNoHighlight: the View explains what happened
// and no row carries the selection marker.
func TestLostSelectionShowsNoticeAndNoHighlight(t *testing.T) {
	m := lostModel(t)
	view := m.View().Content
	if !strings.Contains(view, "pid 20 exited - pick a process") {
		t.Fatalf("view lacks the exit notice:\n%s", view)
	}
	if strings.Contains(view, "> ") {
		t.Fatalf("view highlights a row although the selection is lost:\n%s", view)
	}
}

// TestLostSelectionSurvivesRescansAndEdits: the state is sticky until the user
// moves, so a second rescan or typing cannot re-arm Enter behind their back.
func TestLostSelectionSurvivesRescansAndEdits(t *testing.T) {
	m := lostModel(t)
	m = loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "a"}, ProcessInfo{Pid: 30, Comm: "c"}, ProcessInfo{Pid: 50})
	next, _ := m.Update(tea.KeyPressMsg{Code: 'a', Text: "a"})
	m = next.(Model)
	if m.selectedIndex != noSelection || m.notice == "" {
		t.Fatalf("selectedIndex=%d notice=%q, want the lost state to persist", m.selectedIndex, m.notice)
	}
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v, want a no-op", cmd())
	}
}

// TestLostSelectionClearsOnMove: Up or Down acknowledges the notice and lands
// on the All row; a further Down reaches a process.
func TestLostSelectionClearsOnMove(t *testing.T) {
	for name, code := range map[string]rune{"down": tea.KeyDown, "up": tea.KeyUp} {
		t.Run(name, func(t *testing.T) {
			next, _ := lostModel(t).Update(tea.KeyPressMsg{Code: code})
			m := next.(Model)
			if m.selectedIndex != 0 || m.notice != "" {
				t.Fatalf("selectedIndex=%d notice=%q, want the All row and no notice", m.selectedIndex, m.notice)
			}
			if strings.Contains(m.View().Content, "exited") {
				t.Fatalf("notice still rendered after moving")
			}
		})
	}
	m := pressDown(t, lostModel(t), 2)
	if msg, ok := enterMsg(t, m).(messages.PidSelectedMsg); !ok || msg.Pid != 10 {
		t.Fatalf("Down,Down,Enter emitted %+v, want pid 10", msg)
	}
}

// TestLostSelectionExplicitAllRowStillTracesEverything: the whole-system trace
// stays reachable, but only through a deliberate move onto the All row.
func TestLostSelectionExplicitAllRowStillTracesEverything(t *testing.T) {
	m := pressDown(t, lostModel(t), 1)
	if msg, ok := enterMsg(t, m).(messages.PidSelectedMsg); !ok || msg.Pid != 0 {
		t.Fatalf("Enter on All emitted %+v, want PidSelectedMsg{Pid: 0}", msg)
	}
}
