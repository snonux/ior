package pidpicker

import (
	"errors"
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
	if m.selectedIndex != noSelection || m.notice != m.noMatchNotice() {
		t.Fatalf("selectedIndex=%d notice=%q, want noSelection and the no-match notice", m.selectedIndex, m.notice)
	}
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v, want a no-op without a match", cmd())
	}
	view := m.View().Content
	if !strings.Contains(view, "no process matches the filter") || strings.Contains(view, "> ") {
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

// tidThreadsModel is a TID picker for pid 100 with one main thread and two
// workers.
func tidThreadsModel(t *testing.T) Model {
	t.Helper()
	return loadedModel(t, NewTIDWithKeys(100, DefaultKeyMap()),
		ProcessInfo{Pid: 100, ParentPID: 100, Comm: "main"},
		ProcessInfo{Pid: 101, ParentPID: 100, Comm: "worker"},
		ProcessInfo{Pid: 102, ParentPID: 100, Comm: "worker"})
}

// TestNonEditingKeysKeepUserOwnedAllRowInTIDPicker pins editFilter's "text
// really changed" guard. The user moves onto thread 102, then types "m", which
// hides it: the TID picker falls back to the All TIDs row with the input
// focused. That All row is the user's own, so cursor keys (which reach the
// focused input but do not edit it) must not hand it back to the filter and
// jump to the first match; only a real edit does.
func TestNonEditingKeysKeepUserOwnedAllRowInTIDPicker(t *testing.T) {
	m := typeText(t, pressDown(t, tidThreadsModel(t), 3), "m") // tid 102, then hide it
	if m.selectedIndex != 0 || !m.input.Focused() || m.implicit {
		t.Fatalf("setup: selectedIndex=%d focused=%v implicit=%v, want a focused user-owned All row",
			m.selectedIndex, m.input.Focused(), m.implicit)
	}
	for _, press := range []tea.KeyPressMsg{
		{Code: tea.KeyLeft}, {Code: tea.KeyHome}, {Code: tea.KeyEnd}, {Code: 'a', Mod: tea.ModCtrl},
	} {
		next, _ := m.Update(press)
		m = next.(Model)
		if m.selectedIndex != 0 {
			t.Fatalf("after %v selectedIndex = %d, want the All TIDs row kept", press, m.selectedIndex)
		}
	}
	if msg, ok := enterMsg(t, m).(messages.TidSelectedMsg); !ok || msg != (messages.TidSelectedMsg{}) {
		t.Fatalf("Enter emitted %+v, want the All TIDs message", msg)
	}

	// A real edit then hands the All row to the filter: first match, tid 100.
	// (ctrl+a left the cursor at the start, so move to the end to extend "m".)
	m = typeText(t, pressKey(t, m, tea.KeyEnd), "a")
	if msg, ok := enterMsg(t, m).(messages.TidSelectedMsg); !ok || msg.Tid != 100 {
		t.Fatalf("Enter after editing emitted %+v, want tid 100", msg)
	}
}

// TestUnchangedTextKeepsUserOwnedAllRowInPIDPicker: a paste that adds no text
// focuses the blurred input (Up blurred it) without editing it, so the All row
// the user moved back to must stay.
func TestUnchangedTextKeepsUserOwnedAllRowInPIDPicker(t *testing.T) {
	m := pressKey(t, typeText(t, mysqlModel(t), "my"), tea.KeyUp)
	next, _ := m.Update(tea.PasteMsg{Content: ""})
	m = next.(Model)
	if !m.input.Focused() {
		t.Fatalf("setup: the paste should have focused the input")
	}
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want the All row kept", m.selectedIndex)
	}
	wantPid(t, m, 0)
}

// TestRescanKeepsDerivedFirstMatchByPid: a derived first match is followed by
// pid across a rescan, so a new process sorting ahead of it does not silently
// change what Enter emits.
func TestRescanKeepsDerivedFirstMatchByPid(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysql") // derived selection: pid 30
	m = loadedModel(t, m, ProcessInfo{Pid: 25, Comm: "mysqlx"},
		ProcessInfo{Pid: 30, Comm: "mysqld"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
	if m.selectedIndex != 2 || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want pid 30 kept on row 2 without a notice", m.selectedIndex, m.notice)
	}
	wantPid(t, m, 30)
	// Still derived: the next keystroke re-derives the first match.
	wantPid(t, typeText(t, m, "-"), 40)
}

// TestRescanNoticeWhenDerivedFirstMatchExited: the highlighted first match
// exited, so the next match becomes the selection, which must not be silent.
func TestRescanNoticeWhenDerivedFirstMatchExited(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysql")
	m = loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "bash"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
	if m.selectedIndex != 1 || m.notice != "pid 30 exited - selected pid 40 instead" {
		t.Fatalf("selectedIndex=%d notice=%q, want the move to pid 40 announced", m.selectedIndex, m.notice)
	}
	if view := m.View().Content; !strings.Contains(view, m.notice) {
		t.Fatalf("view lacks the notice:\n%s", view)
	}
	wantPid(t, m, 40)
	if m = pressDown(t, m, 1); m.notice != "" {
		t.Fatalf("notice %q survived Down", m.notice)
	}
}

// TestRescanNoticeIsModeAware: TID mode words the same notice with "tid".
func TestRescanNoticeIsModeAware(t *testing.T) {
	m := typeText(t, tidThreadsModel(t), "work") // derived: tid 101
	m = loadedModel(t, m, ProcessInfo{Pid: 100, ParentPID: 100, Comm: "main"},
		ProcessInfo{Pid: 102, ParentPID: 100, Comm: "worker"})
	if want := "tid 101 exited - selected tid 102 instead"; m.notice != want {
		t.Fatalf("notice = %q, want %q", m.notice, want)
	}
}

// TestNoMatchNoticeWaitsForFirstScan: typing before the first scan result has
// nothing to match yet, which is not the same as "nothing matches", so the red
// notice stays hidden (Enter is still a no-op) until a scan has been seen.
func TestNoMatchNoticeWaitsForFirstScan(t *testing.T) {
	m := typeText(t, NewWithKeys(DefaultKeyMap()), "mysql")
	if m.selectedIndex != noSelection || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want noSelection and no notice before the first scan", m.selectedIndex, m.notice)
	}
	if view := m.View().Content; strings.Contains(view, "matches the filter") {
		t.Fatalf("view shows the no-match notice before the first scan:\n%s", view)
	}
	m = loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "bash"})
	if m.notice != "no process matches the filter" {
		t.Fatalf("notice = %q, want the no-match notice once a scan found nothing", m.notice)
	}
}

// TestNoMatchNoticeSaysThreadInTIDMode: the TID picker lists threads.
func TestNoMatchNoticeSaysThreadInTIDMode(t *testing.T) {
	m := typeText(t, tidThreadsModel(t), "zz")
	if m.notice != "no thread matches the filter" {
		t.Fatalf("notice = %q, want the thread wording", m.notice)
	}
	if view := m.View().Content; !strings.Contains(view, "no thread matches the filter") {
		t.Fatalf("view lacks the thread notice:\n%s", view)
	}
}

// TestRescanNoticeSaysNoLongerMatchesWhenProcessStillRuns: the derived pid is
// still in the scan but no longer matches the filter (it changed its comm), so
// "exited" would be wrong.
func TestRescanNoticeSaysNoLongerMatchesWhenProcessStillRuns(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysql") // derived: pid 30
	m = loadedModel(t, m, ProcessInfo{Pid: 30, Comm: "renamed"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
	if want := "pid 30 no longer matches the filter - selected pid 40 instead"; m.notice != want {
		t.Fatalf("notice = %q, want %q", m.notice, want)
	}
}

// TestScanErrorOnDerivedSelectionShowsOnlyTheError: the failed scan empties the
// list, which is not "nothing matches". The no-match notice would mislead, the
// scan error line already explains the empty list, and Enter stays a no-op.
func TestScanErrorOnDerivedSelectionShowsOnlyTheError(t *testing.T) {
	m := typeText(t, mysqlModel(t), "mysql")
	next, _ := m.Update(processesLoadedMsg{err: errors.New("boom")})
	m = next.(Model)
	if m.selectedIndex != noSelection || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want noSelection and no notice after a failed scan", m.selectedIndex, m.notice)
	}
	view := m.View().Content
	if strings.Contains(view, "matches the filter") || !strings.Contains(view, "scan error: boom") {
		t.Fatalf("view must show the scan error and not the no-match notice:\n%s", view)
	}
	if cmd := enterCmd(m); cmd != nil {
		t.Fatalf("Enter emitted %+v, want a no-op", cmd())
	}
	// A later good scan that finds nothing is a real "no match".
	m = loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "bash"})
	if m.notice != m.noMatchNotice() {
		t.Fatalf("notice = %q, want the no-match notice after a successful empty scan", m.notice)
	}
}

// failScan delivers a failed scan result (no processes, an error).
func failScan(t *testing.T, m Model) Model {
	t.Helper()
	next, _ := m.Update(processesLoadedMsg{err: errors.New("boom")})
	return next.(Model)
}

// TestFailedScanKeepsDerivedPidForNextScan is the hs2 re-review regression: a
// failed scan between two good ones empties the list, and the derived pid 30
// exits meanwhile. The next good scan must still announce the move to pid 40
// like an uninterrupted rescan does, not silently select the new first match.
func TestFailedScanKeepsDerivedPidForNextScan(t *testing.T) {
	m := failScan(t, failScan(t, typeText(t, mysqlModel(t), "mysql"))) // derived: pid 30
	if m.selectedIndex != noSelection || m.notice != "" {
		t.Fatalf("setup: selectedIndex=%d notice=%q, want noSelection without a notice", m.selectedIndex, m.notice)
	}
	m = loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "bash"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
	if want := "pid 30 exited - selected pid 40 instead"; m.notice != want {
		t.Fatalf("notice = %q, want %q", m.notice, want)
	}
	wantPid(t, m, 40)
}

// TestFailedScanKeepsDerivedPidWhenItSurvives: the held pid is still listed
// after the failed scan, so it is selected again (not the new first match 25)
// and nothing needs announcing.
func TestFailedScanKeepsDerivedPidWhenItSurvives(t *testing.T) {
	m := failScan(t, typeText(t, mysqlModel(t), "mysql"))
	m = loadedModel(t, m, ProcessInfo{Pid: 25, Comm: "mysqlx"},
		ProcessInfo{Pid: 30, Comm: "mysqld"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
	if m.selectedIndex != 2 || m.notice != "" {
		t.Fatalf("selectedIndex=%d notice=%q, want pid 30 kept on row 2 without a notice", m.selectedIndex, m.notice)
	}
	wantPid(t, m, 30)
}

// TestHeldPidDroppedByEditAndMove (negative): after the failed scan, a real
// edit or Up/Down starts a new selection, so the next scan must not announce
// the long-gone pid 30.
func TestHeldPidDroppedByEditAndMove(t *testing.T) {
	after := []ProcessInfo{{Pid: 10, Comm: "bash"}, {Pid: 40, Comm: "mysql-proxy"}}
	for name, act := range map[string]func(Model) Model{
		"edit": func(m Model) Model { return pressKey(t, m, tea.KeyBackspace) },
		"up":   func(m Model) Model { return pressKey(t, m, tea.KeyUp) },
		"down": func(m Model) Model { return pressDown(t, m, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			m := act(failScan(t, typeText(t, mysqlModel(t), "mysql")))
			if m = loadedModel(t, m, after...); strings.Contains(m.notice, "pid 30") {
				t.Fatalf("notice = %q, the held pid must be dropped by %s", m.notice, name)
			}
		})
	}
}

// TestHeldPidUsedOnlyByTheNextGoodScan (negative): the good scan after the
// failed one consumes the held pid 30. When a later scan finds no match at all
// (no-match notice) and the one after that brings pid 40, that is an ordinary
// re-derivation from "nothing matched", so no stale "pid 30 ..." notice.
func TestHeldPidUsedOnlyByTheNextGoodScan(t *testing.T) {
	m := failScan(t, typeText(t, mysqlModel(t), "mysql"))
	m = loadedModel(t, m, ProcessInfo{Pid: 30, Comm: "mysqld"}) // held pid 30 back
	wantPid(t, m, 30)
	m = loadedModel(t, m, ProcessInfo{Pid: 10, Comm: "bash"}) // nothing matches
	if m.notice != m.noMatchNotice() {
		t.Fatalf("notice = %q, want the no-match notice", m.notice)
	}
	m = loadedModel(t, m, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
	if m.notice != "" {
		t.Fatalf("notice = %q, want none: pid 30 was no longer held", m.notice)
	}
	wantPid(t, m, 40)
}

// nonEditingMessages reach the focused filter input without changing its text.
func nonEditingMessages() map[string]tea.Msg {
	return map[string]tea.Msg{
		"left":          tea.KeyPressMsg{Code: tea.KeyLeft},
		"right":         tea.KeyPressMsg{Code: tea.KeyRight},
		"home":          tea.KeyPressMsg{Code: tea.KeyHome},
		"end":           tea.KeyPressMsg{Code: tea.KeyEnd},
		"ctrl+a":        tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl},
		"empty paste":   tea.PasteMsg{Content: ""},
		"unrelated msg": struct{ unrelated int }{},
	}
}

// TestNonEditingMessagesKeepDerivedPidAcrossRescan is the hs2 re-review
// regression: after a rescan put a new process ahead of the derived first
// match (pid 30 now on row 2), a message that does not edit the text must not
// rebuild the list and re-derive row 1 (pid 25), which would change what Enter
// emits without a word.
func TestNonEditingMessagesKeepDerivedPidAcrossRescan(t *testing.T) {
	for name, msg := range nonEditingMessages() {
		t.Run(name, func(t *testing.T) {
			m := typeText(t, mysqlModel(t), "mysql") // derived: pid 30
			m = loadedModel(t, m, ProcessInfo{Pid: 25, Comm: "mysqlx"},
				ProcessInfo{Pid: 30, Comm: "mysqld"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
			if m.selectedIndex != 2 {
				t.Fatalf("setup: selectedIndex = %d, want pid 30 kept on row 2", m.selectedIndex)
			}
			next, _ := m.Update(msg)
			m = next.(Model)
			if m.selectedIndex != 2 {
				t.Fatalf("selectedIndex = %d after %s, want pid 30 still on row 2", m.selectedIndex, name)
			}
			wantPid(t, m, 30)

			// A real edit afterwards re-derives the first match from the
			// scan: "mysqld" matches pid 30 only, and deleting the "d"
			// again puts the new pid 25 first. (End: Left and Home moved
			// the cursor, and a typed rune inserts at the cursor.)
			m = typeText(t, pressKey(t, m, tea.KeyEnd), "d")
			wantPid(t, m, 30)
			m = pressKey(t, m, tea.KeyBackspace)
			wantPid(t, m, 25)
		})
	}
}

// TestNonEditingMessagesKeepNoMatchDerivation: with nothing selected by the
// derived no-match state, a non-editing message changes neither state nor
// notice.
func TestNonEditingMessagesKeepNoMatchDerivation(t *testing.T) {
	for name, msg := range nonEditingMessages() {
		t.Run(name, func(t *testing.T) {
			m := typeText(t, mysqlModel(t), "zz")
			next, _ := m.Update(msg)
			got := next.(Model)
			if got.selectedIndex != noSelection || got.notice != m.noMatchNotice() {
				t.Fatalf("selectedIndex=%d notice=%q after %s, want the unchanged no-match state", got.selectedIndex, got.notice, name)
			}
		})
	}
}

// failScanOnUserOwnedAllRow types filter (whose first match the filter
// selects), presses Up to hand the selection to the user on the All row, fails
// a scan and returns the model after checking the All row is still selected.
// The PID and TID pickers share this path (relocateUserSelection), so both are
// pinned through it.
func failScanOnUserOwnedAllRow(t *testing.T, m Model, filter string) Model {
	t.Helper()
	m = pressKey(t, typeText(t, m, filter), tea.KeyUp)
	if m.implicit || m.selectedIndex != 0 {
		t.Fatalf("setup: selectedIndex=%d implicit=%v, want a user-owned All row", m.selectedIndex, m.implicit)
	}
	m = failScan(t, m)
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want the All row kept", m.selectedIndex)
	}
	return m
}

// TestFailedScanOutcomeDependsOnTheSelection pins what a failed scan (an empty
// list plus an error) does to each kind of selection, since only a selection
// derived from a non-empty filter ends up empty-handed:
//   - a derived All row (empty filter) stays: followFilter's empty-query branch
//     does not look at the list, so Enter still means all PIDs;
//   - an All row the user moved back onto stays (relocateUserSelection only
//     clamps it), with the same Enter (all TIDs of the process in the TID
//     picker);
//   - a thread the user picked in the TID picker falls back to All TIDs, which
//     stays inside the process;
//   - a process the user picked in the PID picker is not selected while the list
//     is empty (noSelection, Enter a no-op), without an "exited" notice; the
//     next good scan restores it (userpick_failedscan_test.go).
//
// The derived-row-with-a-filter case is TestScanErrorOnDerivedSelectionShowsOnlyTheError.
func TestFailedScanOutcomeDependsOnTheSelection(t *testing.T) {
	t.Run("derived All row", func(t *testing.T) {
		m := failScan(t, mysqlModel(t))
		if m.selectedIndex != 0 {
			t.Fatalf("selectedIndex = %d, want the All row", m.selectedIndex)
		}
		wantPid(t, m, 0)
	})
	t.Run("user-owned All row", func(t *testing.T) {
		wantPid(t, failScanOnUserOwnedAllRow(t, mysqlModel(t), "my"), 0)
	})
	t.Run("user-owned All TIDs row", func(t *testing.T) {
		m := failScanOnUserOwnedAllRow(t, tidThreadsModel(t), "w")
		if msg, ok := enterMsg(t, m).(messages.TidSelectedMsg); !ok || msg != (messages.TidSelectedMsg{}) {
			t.Fatalf("Enter emitted %+v, want the All TIDs message", msg)
		}
	})
	t.Run("user thread in TID picker", func(t *testing.T) {
		m := failScan(t, pressDown(t, tidThreadsModel(t), 2)) // tid 101
		if msg, ok := enterMsg(t, m).(messages.TidSelectedMsg); !ok || msg != (messages.TidSelectedMsg{}) {
			t.Fatalf("Enter emitted %+v, want the All TIDs message", msg)
		}
	})
	t.Run("user process in PID picker", func(t *testing.T) {
		m := failScan(t, pressDown(t, mysqlModel(t), 3)) // pid 30
		if m.selectedIndex != noSelection {
			t.Fatalf("selectedIndex = %d, want noSelection", m.selectedIndex)
		}
		if cmd := enterCmd(m); cmd != nil {
			t.Fatalf("Enter emitted %+v, want a no-op", cmd())
		}
	})
}
