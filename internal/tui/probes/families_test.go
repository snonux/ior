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

// selectFamily moves the Families cursor onto family.
func selectFamily(t *testing.T, m Model, family types.SyscallFamily) Model {
	t.Helper()
	for m.familyStates()[m.famCursor].Family != family {
		before := m.famCursor
		m, _ = m.Update(keyMsg("j"))
		if m.famCursor == before {
			t.Fatalf("family %s not reachable", family)
		}
	}
	return m
}

// runBatch follows a family batch's command chain to its end, feeding every
// message back through Update as the TUI does, and returns the final model
// and the progress messages seen on the way.
func runBatch(t *testing.T, m Model, cmd tea.Cmd) (Model, []FamilyBatchProgressMsg) {
	t.Helper()
	var progress []FamilyBatchProgressMsg
	for range 100 {
		if cmd == nil {
			t.Fatal("batch command chain ended without a FamilyToggledMsg")
		}
		msg := cmd()
		m, cmd = m.Update(msg)
		switch msg := msg.(type) {
		case FamilyBatchProgressMsg:
			progress = append(progress, msg)
			if m.batchLine() == "" {
				t.Fatal("progress message did not show a progress line")
			}
		case FamilyToggledMsg:
			return m, progress
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
	m, progress := runBatch(t, m, cmd)
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
	m, _ = runBatch(t, m, cmd)
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
	m, _ = runBatch(t, m, cmd)
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
	m := selectFamily(t, openFamilies(t, familyTestManager()), types.FamilyNetwork)
	m, cmd := m.Update(keyMsg("space"))
	m = m.Close()
	m, _ = runBatch(t, m, cmd)
	if m.batch.active || m.lastInfo == "" {
		t.Fatalf("hidden modal did not follow the batch to its end: %+v %q", m.batch, m.lastInfo)
	}
}

func TestFamilyBatchWithoutManagerReportsError(t *testing.T) {
	msg := familyBatchCmd(nil, types.FamilyFS, true)()
	done, ok := msg.(FamilyToggledMsg)
	if !ok || done.Err == nil {
		t.Fatalf("msg = %#v, want a FamilyToggledMsg with an error", msg)
	}
	m, _ := NewModel(nil).Open().Update(done)
	if !strings.Contains(m.lastErr, "FS: probe manager unavailable") {
		t.Fatalf("lastErr = %q", m.lastErr)
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
		{"AIO", "AIO not traced: press o, tab, space to attach"},
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
