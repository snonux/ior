package pidpicker

import (
	"strings"
	"testing"

	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// typeText feeds each rune of text through the real key path, like a user
// typing into the focused filter input.
func typeText(t *testing.T, m Model, text string) Model {
	t.Helper()
	for _, r := range text {
		next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
		m = next.(Model)
	}
	return m
}

// pressKey sends one non-text key through Update.
func pressKey(t *testing.T, m Model, code rune) Model {
	t.Helper()
	next, _ := m.Update(tea.KeyPressMsg{Code: code})
	return next.(Model)
}

// wantPid fails unless Enter emits PidSelectedMsg{Pid: want}.
func wantPid(t *testing.T, m Model, want int) {
	t.Helper()
	msg, ok := enterMsg(t, m).(messages.PidSelectedMsg)
	if !ok || msg.Pid != want {
		t.Fatalf("Enter emitted %+v, want PidSelectedMsg{Pid: %d}", msg, want)
	}
}

// mysqlModel is a PID picker with three processes, only 30 and 40 matching
// "mysql", so the first match is not the first row of the list.
func mysqlModel(t *testing.T) Model {
	t.Helper()
	return loadedModel(t, NewWithKeys(DefaultKeyMap()),
		ProcessInfo{Pid: 10, Comm: "bash"}, ProcessInfo{Pid: 20, Comm: "sshd"},
		ProcessInfo{Pid: 30, Comm: "mysqld"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
}

// TestTypingMovesSelectionToFirstMatch is the task hs2 regression: typing a
// filter and pressing Enter must pick the first match, not the All row whose
// Enter is a whole-system trace (PidSelectedMsg{Pid: 0}).
func TestTypingMovesSelectionToFirstMatch(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysql")
	if m.selectedIndex != 1 {
		t.Fatalf("selectedIndex = %d, want 1 (first match)", m.selectedIndex)
	}
	wantPid(t, m, 30)
}

// TestUntypedPickerStillStartsOnAllRow: without a filter the initial All
// selection is unchanged, a deliberate bare Enter still means all PIDs.
func TestUntypedPickerStillStartsOnAllRow(t *testing.T) {
	m := mysqlModel(t)
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want 0", m.selectedIndex)
	}
	wantPid(t, m, 0)
}

// TestFirstMatchFollowsEachKeystroke: refining the filter re-derives the first
// match, it does not stay on the row number or the previous first match.
func TestFirstMatchFollowsEachKeystroke(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysql")
	m = typeText(t, m, "-")
	wantPid(t, m, 40)
	m = pressKey(t, m, tea.KeyBackspace)
	wantPid(t, m, 30)
}

// TestNoMatchSelectsNothing is the negative case: a filter that matches no
// process must not leave the All row armed. Enter does nothing, the view
// explains why and no row is highlighted.
func TestNoMatchSelectsNothing(t *testing.T) {
	m := typeText(t, mysqlModel(t), "nosuchprocess")
	if m.selectedIndex != noSelection || m.notice != noMatchNotice {
		t.Fatalf("selectedIndex=%d notice=%q, want noSelection and the no-match notice", m.selectedIndex, m.notice)
	}
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v, want a no-op without a match", cmd())
	}
	view := m.View().Content
	if !strings.Contains(view, noMatchNotice) || strings.Contains(view, "> ") {
		t.Fatalf("view lacks the notice or highlights a row:\n%s", view)
	}
}

// TestNoMatchRecoversWhenBackspaceFindsMatches: the no-match state is derived,
// not sticky, so deleting the stray character re-selects the first match and
// clears the notice.
func TestNoMatchRecoversWhenBackspaceFindsMatches(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysqlx")
	if m.selectedIndex != noSelection {
		t.Fatalf("setup: selectedIndex = %d, want noSelection", m.selectedIndex)
	}
	m = pressKey(t, m, tea.KeyBackspace)
	if m.selectedIndex != 1 || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want the first match and no notice", m.selectedIndex, m.notice)
	}
	wantPid(t, m, 30)
}

// TestClearingFilterReturnsToAllRow: when the filter is emptied again the
// automatic selection goes back to the initial All row rather than leaving
// Enter on whatever process sits first in the unfiltered list.
func TestClearingFilterReturnsToAllRow(t *testing.T) {
	m := typeText(t, mysqlModel(t), "my")
	for i := 0; i < 2; i++ {
		m = pressKey(t, m, tea.KeyBackspace)
	}
	if m.selectedIndex != 0 || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want the All row and no notice", m.selectedIndex, m.notice)
	}
	wantPid(t, m, 0)
}

// TestClearingNoMatchFilterReturnsToAllRow: same for a filter that never
// matched anything.
func TestClearingNoMatchFilterReturnsToAllRow(t *testing.T) {
	m := typeText(t, mysqlModel(t), "zz")
	m = pressKey(t, pressKey(t, m, tea.KeyBackspace), tea.KeyBackspace)
	if m.selectedIndex != 0 || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want the All row and no notice", m.selectedIndex, m.notice)
	}
}

// TestUpReachesAllRowAfterTyping: the whole-system trace stays one deliberate
// keypress away, Up from the first match highlights All and Enter honours it.
func TestUpReachesAllRowAfterTyping(t *testing.T) {
	m := pressKey(t, typeText(t, mysqlModel(t), "mysql"), tea.KeyUp)
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want 0 after Up", m.selectedIndex)
	}
	wantPid(t, m, 0)
}

// TestDownFromNoMatchLandsOnAllRow: acknowledging the no-match state with a
// move behaves like the lost-selection state, All first and then deliberate.
func TestDownFromNoMatchLandsOnAllRow(t *testing.T) {
	m := pressKey(t, typeText(t, mysqlModel(t), "zz"), tea.KeyDown)
	if m.selectedIndex != 0 || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want the All row and no notice", m.selectedIndex, m.notice)
	}
	wantPid(t, m, 0)
}

// TestTypingAfterReturningToAllHandsItBackToTheFilter: the user pressed Up onto
// All and then keeps typing. The highlight must not stay on All, or the next
// Enter would again be the unintended whole-system trace.
func TestTypingAfterReturningToAllHandsItBackToTheFilter(t *testing.T) {
	m := pressKey(t, typeText(t, mysqlModel(t), "my"), tea.KeyUp)
	m = typeText(t, m, "sql")
	if m.selectedIndex != 1 {
		t.Fatalf("selectedIndex = %d, want 1 (first match)", m.selectedIndex)
	}
	wantPid(t, m, 30)
}

// TestExplicitAllRowSurvivesARescan: only editing the filter text hands the All
// row back; a rescan under an unchanged filter keeps the user's own choice.
func TestExplicitAllRowSurvivesARescan(t *testing.T) {
	m := pressKey(t, typeText(t, mysqlModel(t), "mysql"), tea.KeyUp)
	m = loadedModel(t, m, ProcessInfo{Pid: 30, Comm: "mysqld"}, ProcessInfo{Pid: 50, Comm: "mysqlx"})
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want the explicit All row kept", m.selectedIndex)
	}
}

// TestSelectedProcessBeatsFirstMatch: the 6r2 rule still wins. A process the
// user moved onto stays selected while it matches, even though it is not the
// first match.
func TestSelectedProcessBeatsFirstMatch(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysql")
	m = pressDown(t, m, 1) // pid 40, the second match
	m = typeText(t, m, "-")
	wantPid(t, m, 40)
	m = pressKey(t, m, tea.KeyBackspace)
	wantPid(t, m, 40)
}

// TestUserSelectedProcessStillLostWhenFilterHidesIt: the lost-selection state
// is unchanged for a process the user moved onto: no-op Enter, never row 1.
func TestUserSelectedProcessStillLostWhenFilterHidesIt(t *testing.T) {
	m := pressDown(t, mysqlModel(t), 2) // pid 20 sshd
	m = typeText(t, m, "mysql")
	if m.selectedIndex != noSelection || !strings.Contains(m.notice, "pid 20 no longer matches") {
		t.Fatalf("selectedIndex=%d notice=%q, want the lost-selection state for pid 20", m.selectedIndex, m.notice)
	}
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v, want a no-op", cmd())
	}
}

// TestFilterTypedBeforeFirstScanSelectsFirstMatch: typing can beat the initial
// scan. With nothing to match yet Enter is a no-op, and once the scan arrives
// the first match is selected.
func TestFilterTypedBeforeFirstScanSelectsFirstMatch(t *testing.T) {
	m := typeText(t, NewWithKeys(DefaultKeyMap()), "mysql")
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v before any scan result matched, want a no-op", cmd())
	}
	m = loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "bash"}, ProcessInfo{Pid: 30, Comm: "mysqld"})
	wantPid(t, m, 30)
}

// TestPasteMovesSelectionToFirstMatch: a pasted filter is typing too.
func TestPasteMovesSelectionToFirstMatch(t *testing.T) {
	next, _ := mysqlModel(t).Update(tea.PasteMsg{Content: "mysql"})
	wantPid(t, next.(Model), 30)
}

// TestWhitespaceOnlyFilterKeepsAllRow: a query that trims to nothing is no
// filter, the list is complete and the All row stays the initial selection.
func TestWhitespaceOnlyFilterKeepsAllRow(t *testing.T) {
	m := typeText(t, mysqlModel(t), "  ")
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want 0", m.selectedIndex)
	}
}

// TestTIDPickerTypingSelectsFirstMatch: the TID picker follows the same rule,
// and a filter without a match does not fall back to All TIDs either.
func TestTIDPickerTypingSelectsFirstMatch(t *testing.T) {
	m := loadedModel(t, NewTIDWithKeys(100, DefaultKeyMap()),
		ProcessInfo{Pid: 100, ParentPID: 100, Comm: "main"},
		ProcessInfo{Pid: 101, ParentPID: 100, Comm: "worker"},
		ProcessInfo{Pid: 102, ParentPID: 100, Comm: "worker"})
	typed := typeText(t, m, "work")
	msg, ok := enterMsg(t, typed).(messages.TidSelectedMsg)
	if !ok || msg.Pid != 100 || msg.Tid != 101 {
		t.Fatalf("Enter emitted %+v, want TidSelectedMsg{Pid: 100, Tid: 101}", msg)
	}

	none := typeText(t, m, "zz")
	if none.selectedIndex != noSelection {
		t.Fatalf("selectedIndex = %d, want noSelection", none.selectedIndex)
	}
	if cmd := enterCmd(none); cmd != nil {
		t.Fatalf("Enter emitted %+v, want a no-op without a match", cmd())
	}
}
