package probes

import (
	"strings"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// familyTestManager has read/write (FS, read attached), socket/connect
// (Network, none attached) and nanosleep (Time).
func familyTestManager() *fakeManager {
	return &fakeManager{states: []probemanager.ProbeState{
		{Syscall: "connect"},
		{Syscall: "nanosleep"},
		{Syscall: "read", Active: true},
		{Syscall: "socket"},
		{Syscall: "write"},
	}}
}

// openFamilies opens the modal on fm and switches to the Families view.
func openFamilies(t *testing.T, fm *fakeManager) Model {
	t.Helper()
	m, _ := NewModel(fm).SetSize(100, 40).Open().Update(keyMsg("tab"))
	if m.view != viewFamilies {
		t.Fatal("tab did not switch to the Families view")
	}
	return m
}

// selectFamily moves the Families cursor onto family, starting from the top.
func selectFamily(t *testing.T, m Model, family types.SyscallFamily) Model {
	t.Helper()
	for m.famCursor > 0 {
		m, _ = m.Update(keyMsg("k"))
	}
	for m.familyStates()[m.famCursor].Family != family {
		before := m.famCursor
		m, _ = m.Update(keyMsg("j"))
		if m.famCursor == before {
			t.Fatalf("family %s not reachable", family)
		}
	}
	return m
}

// runBatch plays the TUI's part for the family batch the modal requested
// with cmd: it checks the request, starts the batch with StartFamilyBatch on
// fm, follows the command chain to its end, rendering every message into the
// modal as the TUI does, and returns the final model and the progress seen.
func runBatch(t *testing.T, m Model, fm *fakeManager, cmd tea.Cmd) (Model, []FamilyBatchProgressMsg) {
	t.Helper()
	if cmd == nil {
		t.Fatal("the modal requested no batch")
	}
	req, ok := cmd().(FamilyBatchRequestMsg)
	if !ok {
		t.Fatal("the modal's command is not a FamilyBatchRequestMsg")
	}
	var progress []FamilyBatchProgressMsg
	next := StartFamilyBatch(fm, 7, req.Family, req.Attach)
	for range 100 {
		switch msg := next().(type) {
		case FamilyBatchProgressMsg:
			if msg.Run != 7 {
				t.Fatalf("progress of run %d, want 7", msg.Run)
			}
			progress = append(progress, msg)
			m = m.ShowBatchProgress(msg)
			if m.batchLine() == "" {
				t.Fatal("progress message did not show a progress line")
			}
			next = msg.Next()
		case FamilyToggledMsg:
			if msg.Run != 7 {
				t.Fatalf("result of run %d, want 7", msg.Run)
			}
			return m.FinishBatch(msg, ""), progress
		default:
			t.Fatalf("unexpected batch message %T", msg)
		}
	}
	t.Fatal("batch did not finish")
	return m, nil
}

func TestFamiliesViewListsEveryFamilyWithCounts(t *testing.T) {
	m := openFamilies(t, familyTestManager())
	view := m.View(100, 40)
	if !strings.Contains(view, "Probes (1/5 active) - Families") {
		t.Fatalf("title missing from view:\n%s", view)
	}
	for _, family := range types.AllSyscallFamilies() {
		if !strings.Contains(view, string(family)) {
			t.Fatalf("family %s missing from view:\n%s", family, view)
		}
	}
	for _, row := range []string{"[ ] Network       0/2", "[~] FS            1/2", "[ ] AIO           0/0"} {
		if !strings.Contains(view, row) {
			t.Fatalf("row %q missing from view:\n%s", row, view)
		}
	}
	// tab switches back.
	if back, _ := m.Update(keyMsg("tab")); back.view != viewSyscalls {
		t.Fatal("second tab did not return to the Syscalls view")
	}
}

func TestFamilyToggleAttachesWholeFamilyWithProgress(t *testing.T) {
	fm := familyTestManager()
	m := selectFamily(t, openFamilies(t, fm), types.FamilyNetwork)
	m, cmd := m.Update(keyMsg("space"))
	if !m.batch.active || cmd == nil {
		t.Fatal("space on a family did not start a batch")
	}
	m, progress := runBatch(t, m, fm, cmd)
	if len(progress) == 0 || progress[0].Family != types.FamilyNetwork || !progress[0].Attach {
		t.Fatalf("progress = %+v, want Network attach updates", progress)
	}
	if m.batch.active {
		t.Fatal("batch still marked active after it finished")
	}
	if got := m.familyStates()[m.famCursor]; got.Active != 2 {
		t.Fatalf("Network = %+v, want both probes attached", got)
	}
	if !strings.Contains(m.View(100, 40), "Network: attached 2 of 2 probes") {
		t.Fatalf("outcome line missing:\n%s", m.View(100, 40))
	}
}

func TestFamilyToggleDetachesPartiallyAttachedFamily(t *testing.T) {
	fm := familyTestManager()
	m := selectFamily(t, openFamilies(t, fm), types.FamilyFS)
	m, cmd := m.Update(keyMsg("enter"))
	m, _ = runBatch(t, m, fm, cmd)
	if got := m.familyStates()[m.famCursor]; got.Active != 0 || got.Total != 2 {
		t.Fatalf("FS = %+v, want 0/2 after detach", got)
	}
	if !strings.Contains(m.lastInfo, "FS: detached 1 of 1 probes") {
		t.Fatalf("lastInfo = %q", m.lastInfo)
	}
}

func TestFamilyToggleReportsPerSyscallFailures(t *testing.T) {
	fm := familyTestManager()
	fm.failAttach = map[string]bool{"connect": true}
	m := selectFamily(t, openFamilies(t, fm), types.FamilyNetwork)
	m, cmd := m.Update(keyMsg("space"))
	m, _ = runBatch(t, m, fm, cmd)
	if !strings.Contains(m.lastInfo, "attached 1 of 2") {
		t.Fatalf("lastInfo = %q, want 1 of 2 attached", m.lastInfo)
	}
	if !strings.Contains(m.lastErr, "1 failed, first connect: no tracepoint") {
		t.Fatalf("lastErr = %q, want the connect failure", m.lastErr)
	}
}

func TestFamilyToggleIgnoredWhileBatchRunsAndOnEmptyFamily(t *testing.T) {
	m := selectFamily(t, openFamilies(t, familyTestManager()), types.FamilyNetwork)
	m.batch = familyBatch{active: true, family: types.FamilyTime, attach: true}
	if _, cmd := m.Update(keyMsg("space")); cmd != nil {
		t.Fatal("a second batch started while one was running")
	}
	m.batch = familyBatch{}
	m = selectFamily(t, m, types.FamilyAIO)
	m, cmd := m.Update(keyMsg("space"))
	if cmd != nil || !strings.Contains(m.lastErr, "AIO has no probes") {
		t.Fatalf("empty family: cmd %v lastErr %q; want no batch and an explanation", cmd != nil, m.lastErr)
	}
}

func TestFamilyBatchFinishesWhileModalHidden(t *testing.T) {
	fm := familyTestManager()
	m := selectFamily(t, openFamilies(t, fm), types.FamilyNetwork)
	m, cmd := m.Update(keyMsg("space"))
	m = m.Close()
	m, _ = runBatch(t, m, fm, cmd)
	if m.batch.active || m.lastInfo == "" {
		t.Fatalf("hidden modal did not render the batch's end: %+v %q", m.batch, m.lastInfo)
	}
}

// TestDetachProgressTotalCountsAttachedProbes: the provisional total shown
// before the first update is the number of probes the batch will change -
// for a detach the attached ones (1 of FS's 2), for an attach the detached.
func TestDetachProgressTotalCountsAttachedProbes(t *testing.T) {
	m := selectFamily(t, openFamilies(t, familyTestManager()), types.FamilyFS)
	m, _ = m.Update(keyMsg("space"))
	if m.batch.attach || m.batch.total != 1 {
		t.Fatalf("FS detach batch = %+v, want total 1", m.batch)
	}
	m.batch = familyBatch{}
	m = selectFamily(t, m, types.FamilyNetwork)
	m, _ = m.Update(keyMsg("space"))
	if !m.batch.attach || m.batch.total != 2 {
		t.Fatalf("Network attach batch = %+v, want total 2", m.batch)
	}
}

func TestFamilyBatchWithoutManagerReportsError(t *testing.T) {
	msg := StartFamilyBatch(nil, 3, types.FamilyFS, true)()
	done, ok := msg.(FamilyToggledMsg)
	if !ok || done.Err == nil || done.Run != 3 {
		t.Fatalf("msg = %#v, want run 3's FamilyToggledMsg with an error", msg)
	}
	m := NewModel(nil).Open().FinishBatch(done, "")
	if !strings.Contains(m.lastErr, "FS: probe manager unavailable") {
		t.Fatalf("lastErr = %q", m.lastErr)
	}
}

func TestFocusFamilyPreselectsFamiliesCursor(t *testing.T) {
	m := NewModel(familyTestManager()).FocusFamily("Time").Open()
	m, _ = m.Update(keyMsg("tab"))
	if got := m.familyStates()[m.famCursor].Family; got != types.FamilyTime {
		t.Fatalf("cursor on %s, want Time", got)
	}
	if m = m.FocusFamily("Bogus"); m.familyStates()[m.famCursor].Family != types.FamilyTime {
		t.Fatal("an unknown family moved the cursor")
	}
}

func TestFinishBatchAppendsNote(t *testing.T) {
	m := NewModel(familyTestManager()).Open().FinishBatch(FamilyToggledMsg{Family: types.FamilyFS, Attach: true}, "(note)")
	if !strings.HasSuffix(m.lastInfo, " (note)") {
		t.Fatalf("lastInfo = %q, want the note appended", m.lastInfo)
	}
}

func TestFamiliesViewIgnoresSyscallOnlyKeys(t *testing.T) {
	fm := familyTestManager()
	m := openFamilies(t, fm)
	for _, key := range []string{"/", "f", "a", "n"} {
		next, cmd := m.Update(keyMsg(key))
		if next.searching || cmd != nil {
			t.Fatalf("key %q acted in the Families view", key)
		}
	}
	if len(fm.toggles) != 0 {
		t.Fatalf("toggles = %v, want none", fm.toggles)
	}
}

func TestNotTracedHint(t *testing.T) {
	states := []probemanager.ProbeState{{Syscall: "read", Active: true}, {Syscall: "socket"}}
	tests := []struct {
		family string
		want   string
	}{
		{"", ""},
		{"FS", ""},
		{"Network", "Network not traced: press o, tab, space to attach"},
		{"AIO", ""}, // no probe at all: nothing to attach
	}
	for _, tt := range tests {
		if got := NotTracedHint(tt.family, states); got != tt.want {
			t.Errorf("NotTracedHint(%q) = %q, want %q", tt.family, got, tt.want)
		}
	}
}

func TestClampWindow(t *testing.T) {
	tests := []struct {
		name                    string
		cursor, offset, n, rows int
		wantCursor, wantOffset  int
	}{
		{"empty list", 5, 3, 0, 4, 0, 0},
		{"cursor past end", 20, 0, 12, 4, 11, 8},
		{"negative cursor", -1, 0, 12, 4, 0, 0},
		{"scroll up to cursor", 2, 5, 12, 4, 2, 2},
		{"grown budget pulls offset back", 11, 8, 12, 12, 11, 0},
	}
	for _, tt := range tests {
		cursor, offset := clampWindow(tt.cursor, tt.offset, tt.n, tt.rows)
		if cursor != tt.wantCursor || offset != tt.wantOffset {
			t.Errorf("%s: got (%d, %d), want (%d, %d)", tt.name, cursor, offset, tt.wantCursor, tt.wantOffset)
		}
	}
}

// keyMsg builds the key press for a key name as Model.handleKeyPress sees it
// (msg.String()): "tab", "enter" and "space" are special keys, anything else
// a printable rune.
func keyMsg(name string) tea.KeyPressMsg {
	switch name {
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "space":
		return tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	}
	r := []rune(name)[0]
	return tea.KeyPressMsg{Code: r, Text: name}
}

func TestKeyMsgMatchesHandledNames(t *testing.T) {
	for _, name := range []string{"tab", "enter", "space", "j", "/"} {
		if got := keyMsg(name).String(); got != name {
			t.Errorf("keyMsg(%q).String() = %q", name, got)
		}
	}
}

// TestSyscallChangesRefusedWhileFamilyBatchRuns: space/enter, a and n would
// race the batch's own attaches or detaches, so they are refused with a
// notice while a batch is shown as running; moving and searching still work.
func TestSyscallChangesRefusedWhileFamilyBatchRuns(t *testing.T) {
	fm := familyTestManager()
	m := NewModel(fm).SetSize(100, 40).Open().
		ShowBatchProgress(FamilyBatchProgressMsg{Family: types.FamilyNetwork, Attach: true, Total: 2})
	for _, key := range []string{"space", "enter", "a", "n"} {
		next, cmd := m.Update(keyMsg(key))
		if cmd != nil {
			t.Fatalf("key %q started a probe change while a family batch runs", key)
		}
		if !strings.Contains(next.View(100, 40), "family batch running") {
			t.Fatalf("key %q: refusal not shown:\n%s", key, next.View(100, 40))
		}
	}
	if next, _ := m.Update(keyMsg("j")); next.cursor != 1 {
		t.Fatal("navigation blocked while a family batch runs")
	}
	if len(fm.toggles)+len(fm.changes) != 0 {
		t.Fatalf("probes changed: toggles %v changes %v", fm.toggles, fm.changes)
	}
	// Once the batch has finished, the keys work again.
	m = m.FinishBatch(FamilyToggledMsg{Family: types.FamilyNetwork, Attach: true}, "")
	if _, cmd := m.Update(keyMsg("a")); cmd == nil {
		t.Fatal("a refused after the batch finished")
	}
}
