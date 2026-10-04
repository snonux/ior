package common

import (
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestExecTrackingCoversTheChildAndSignalsIt(t *testing.T) {
	if ExecActive() {
		t.Fatal("ExecActive() before any exec")
	}
	SignalExec(syscall.SIGTERM) // no child: must be a harmless no-op

	run := &trackedExec{Cmd: exec.Command("sleep", "30")}
	errc := make(chan error, 1)
	go func() { errc <- run.Run() }()
	waitUntil(t, func() bool {
		execState.mu.Lock()
		defer execState.mu.Unlock()
		return execState.active && execState.proc != nil
	})
	if !ExecActive() {
		t.Fatal("ExecActive() = false while the child runs")
	}
	SignalExec(syscall.SIGTERM)
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "terminated") {
			t.Fatalf("Run() = %v, want the child's termination", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM did not end the child")
	}
	if ExecActive() {
		t.Fatal("ExecActive() = true after the child exited")
	}
}

func TestExecTrackingIsClearedWhenTheChildCannotStart(t *testing.T) {
	run := &trackedExec{Cmd: exec.Command("/nonexistent/ior-test-binary")}
	if err := run.Run(); err == nil {
		t.Fatal("Run() = nil for a missing binary")
	}
	if ExecActive() {
		t.Fatal("ExecActive() = true after a failed start")
	}
}

func TestExecTrackingKeepsCallerRedirections(t *testing.T) {
	var out strings.Builder
	c := exec.Command("true")
	c.Stdout = &out
	run := &trackedExec{Cmd: c}
	run.SetStdout(&strings.Builder{})
	if c.Stdout != &out {
		t.Fatal("SetStdout replaced the command's own stdout")
	}
	c2 := exec.Command("true")
	run2 := &trackedExec{Cmd: c2}
	var terminal strings.Builder
	run2.SetStdout(&terminal)
	if c2.Stdout != &terminal {
		t.Fatal("SetStdout did not give an unset stdout the terminal")
	}
}
