package pidpicker

import (
	"strings"
	"testing"

	"ior/internal/tui/messages"
)

// Tasks fz2 and hz2: a failed scan only says the list is empty, it does not
// say the process the user picked exited. The picker must not claim so, and
// the next good scan must put the pick back when the process is still there.

func goodScan(t *testing.T, m Model, procs ...ProcessInfo) Model {
	t.Helper()
	next, _ := m.Update(processesLoadedMsg{processes: procs})
	return next.(Model)
}

func mysqlProcesses() []ProcessInfo {
	return []ProcessInfo{{Pid: 10, Comm: "bash"}, {Pid: 20, Comm: "sshd"},
		{Pid: 30, Comm: "mysqld"}, {Pid: 40, Comm: "mysql-proxy"}}
}

func TestFailedScanDoesNotClaimTheUserPickedProcessExited(t *testing.T) {
	m := failScan(t, pressDown(t, mysqlModel(t), 3)) // the user picked pid 30
	if m.selectedIndex != noSelection {
		t.Fatalf("selectedIndex = %d, want noSelection while the list is empty", m.selectedIndex)
	}
	if strings.Contains(m.notice, "exited") || m.notice != "" {
		t.Fatalf("notice = %q after a failed scan, want none (the scan error line explains it)", m.notice)
	}
}

func TestUserPickedProcessIsRestoredByTheNextGoodScan(t *testing.T) {
	m := failScan(t, failScan(t, pressDown(t, mysqlModel(t), 3))) // two failures in a row
	m = goodScan(t, m, append([]ProcessInfo{{Pid: 5, Comm: "new"}}, mysqlProcesses()...)...)
	wantPid(t, m, 30) // sorted differently now, still pid 30
	if m.notice != "" {
		t.Fatalf("notice = %q, want none after the restore", m.notice)
	}
}

func TestUserPickThatReallyExitedIsReportedByTheNextGoodScan(t *testing.T) {
	m := failScan(t, pressDown(t, mysqlModel(t), 3))
	m = goodScan(t, m, ProcessInfo{Pid: 10, Comm: "bash"}, ProcessInfo{Pid: 40, Comm: "mysql-proxy"})
	if m.selectedIndex != noSelection || !strings.Contains(m.notice, "pid 30 exited") {
		t.Fatalf("selectedIndex = %d, notice = %q, want noSelection and the exited notice", m.selectedIndex, m.notice)
	}
}

func TestMovingAfterAFailedScanDropsTheHeldPick(t *testing.T) {
	m := failScan(t, pressDown(t, mysqlModel(t), 3))
	m = pressDown(t, m, 1) // from noSelection to the All row: the user chose again
	m = goodScan(t, m, mysqlProcesses()...)
	if m.selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want the All row the user moved to, not the old pick", m.selectedIndex)
	}
}

func TestUserPickedThreadIsRestoredInTheTIDPicker(t *testing.T) {
	m := failScan(t, pressDown(t, tidThreadsModel(t), 2)) // tid 101
	if msg, ok := enterMsg(t, m).(messages.TidSelectedMsg); !ok || msg != (messages.TidSelectedMsg{}) {
		t.Fatalf("Enter after the failed scan emitted %+v, want the All TIDs message", msg)
	}
	m = goodScan(t, m,
		ProcessInfo{Pid: 100, ParentPID: 100, Comm: "main"},
		ProcessInfo{Pid: 101, ParentPID: 100, Comm: "worker"},
		ProcessInfo{Pid: 102, ParentPID: 100, Comm: "worker"})
	if msg, ok := enterMsg(t, m).(messages.TidSelectedMsg); !ok || msg.Tid != 101 || msg.Pid != 100 {
		t.Fatalf("Enter after the good scan emitted %+v, want thread 101 of process 100", msg)
	}
}
