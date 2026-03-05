package pidpicker

import (
	"ior/internal/tui/messages"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestApplyFilterByPIDCommAndCmdline(t *testing.T) {
	m := NewWithKeys(DefaultKeyMap())
	m.processes = []ProcessInfo{
		{Pid: 100, Comm: "bash", Cmdline: "bash -l"},
		{Pid: 200, Comm: "sshd", Cmdline: "/usr/sbin/sshd -D"},
	}

	m.input.SetValue("200")
	m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Pid != 200 {
		t.Fatalf("expected pid filter to keep only 200, got %+v", m.filtered)
	}

	m.input.SetValue("BASH")
	m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Pid != 100 {
		t.Fatalf("expected comm filter to keep only 100, got %+v", m.filtered)
	}

	m.input.SetValue("/usr/sbin")
	m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Pid != 200 {
		t.Fatalf("expected cmdline filter to keep only 200, got %+v", m.filtered)
	}
}

func TestEnterEmitsAllPIDsAndSelectedPID(t *testing.T) {
	m := NewWithKeys(DefaultKeyMap())
	m.processes = []ProcessInfo{{Pid: 7, Comm: "vim"}, {Pid: 9, Comm: "top"}}
	m.applyFilter()

	modelAny, cmdAny := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = modelAny
	msgAny := cmdAny()
	pidAny, ok := msgAny.(messages.PidSelectedMsg)
	if !ok {
		t.Fatalf("expected PidSelectedMsg for all-pids selection, got %T", msgAny)
	}
	if pidAny.Pid != 0 {
		t.Fatalf("expected all-pids to emit pid 0, got %d", pidAny.Pid)
	}

	m.selectedIndex = 2
	modelOne, cmdOne := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = modelOne
	msgOne := cmdOne()
	pidOne, ok := msgOne.(messages.PidSelectedMsg)
	if !ok {
		t.Fatalf("expected PidSelectedMsg for concrete selection, got %T", msgOne)
	}
	if pidOne.Pid != 9 {
		t.Fatalf("expected selected pid 9, got %d", pidOne.Pid)
	}
}

func TestEnterEmitsAllTIDsAndSelectedTIDInTIDMode(t *testing.T) {
	m := NewTIDWithKeys(42, DefaultKeyMap())
	m.processes = []ProcessInfo{
		{Pid: 7001, ParentPID: 42, Comm: "main"},
		{Pid: 7002, ParentPID: 42, Comm: "worker"},
	}
	m.applyFilter()

	modelAny, cmdAny := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = modelAny
	msgAny := cmdAny()
	tidAny, ok := msgAny.(messages.TidSelectedMsg)
	if !ok {
		t.Fatalf("expected TidSelectedMsg for all-tids selection, got %T", msgAny)
	}
	if tidAny.Tid != 0 {
		t.Fatalf("expected all-tids to emit tid 0, got %d", tidAny.Tid)
	}
	if tidAny.Pid != 0 {
		t.Fatalf("expected all-tids to emit pid 0, got %d", tidAny.Pid)
	}

	m.selectedIndex = 2
	modelOne, cmdOne := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = modelOne
	msgOne := cmdOne()
	tidOne, ok := msgOne.(messages.TidSelectedMsg)
	if !ok {
		t.Fatalf("expected TidSelectedMsg for concrete selection, got %T", msgOne)
	}
	if tidOne.Tid != 7002 {
		t.Fatalf("expected selected tid 7002, got %d", tidOne.Tid)
	}
	if tidOne.Pid != 42 {
		t.Fatalf("expected selected pid 42, got %d", tidOne.Pid)
	}
}

func TestEscQuitsAndRefreshTriggersScan(t *testing.T) {
	m := NewWithKeys(DefaultKeyMap())

	_, escCmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if escCmd == nil {
		t.Fatalf("expected esc to return quit cmd")
	}
	if msg := escCmd(); msg != (tea.QuitMsg{}) {
		t.Fatalf("expected quit msg from esc, got %T", msg)
	}

	_, refreshCmd := m.Update(tea.KeyPressMsg{Code: rune('r'), Text: "r", Mod: tea.ModCtrl})
	if refreshCmd == nil {
		t.Fatalf("expected refresh cmd")
	}
	if _, ok := refreshCmd().(processesLoadedMsg); !ok {
		t.Fatalf("expected refresh to emit processesLoadedMsg")
	}
}

func TestRuneRDoesNotTriggerRefreshWhileFilterFocused(t *testing.T) {
	m := NewWithKeys(DefaultKeyMap())

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'r'}[0], Text: string([]rune{'r'})})
	if cmd == nil {
		t.Fatalf("expected textinput update cmd")
	}

	updated := next.(Model)
	if got := updated.input.Value(); got != "r" {
		t.Fatalf("expected filter input to contain typed r, got %q", got)
	}
}

func TestRenderRowsKeepsSelectionVisible(t *testing.T) {
	m := NewWithKeys(DefaultKeyMap())
	m.height = 8 // visible rows == 2
	m.processes = []ProcessInfo{
		{Pid: 1, Comm: "p1"},
		{Pid: 2, Comm: "p2"},
		{Pid: 3, Comm: "p3"},
		{Pid: 4, Comm: "p4"},
	}
	m.applyFilter()
	m.selectedIndex = 4

	rows := m.renderRows()
	if !strings.Contains(rows, "> 4  p4") {
		t.Fatalf("expected selected row to remain visible, got:\n%s", rows)
	}
}
