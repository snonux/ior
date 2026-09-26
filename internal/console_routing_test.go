package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"ior/internal/probemanager"
)

// The event loop and BPF setup run while Bubble Tea owns the terminal (every
// TUI trace restart re-runs both), so neither may write to stdout/stderr
// directly: all human-facing lines go through an injected logger, which is a
// no-op in TUI mode and stderr in headless modes. These tests pin that routing.

// lineRecorder is a concurrency-safe func(...any) logger sink.
type lineRecorder struct {
	mu  sync.Mutex
	got []string
}

func (r *lineRecorder) log(args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}

func (r *lineRecorder) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

func (r *lineRecorder) joined() string {
	return strings.Join(r.lines(), "\n")
}

// failOnLog returns a logger that fails the test when anything is logged.
func failOnLog(t *testing.T) func(...any) {
	t.Helper()
	return func(args ...any) {
		t.Errorf("unexpected log line: %q", fmt.Sprint(args...))
	}
}

// runCancelledEventLoop runs a loop whose context is already cancelled, so
// run returns through the ctx.Done arm (the TUI trace-restart path), and then
// collects the end-of-run stats as the shutdown watcher does.
func runCancelledEventLoop(t *testing.T, el *eventLoop) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	el.run(ctx, make(chan []byte))
	_ = el.stats()
}

func TestEventLoopLifecycleLinesFollowStatusCallback(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{pprofEnable: true})
	rec := &lineRecorder{}
	el.SetStatusCallback(rec.log)

	stdout, stderr := captureConsole(t, func() { runCancelledEventLoop(t, el) })

	requireNoConsoleOutput(t, stdout, stderr)
	want := []string{
		"Profiling, press Ctrl+C to stop",
		"Stopping event loop",
		"Waiting for stats to be ready",
	}
	if got := rec.lines(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("status lines = %q, want %q", got, want)
	}
}

// TestEventLoopSilentStatusCallbackKeepsTerminalClean is the TUI case: logln
// is a no-op there, and a cancelled run (each trace restart) must not print
// "Stopping event loop" over the dashboard.
func TestEventLoopSilentStatusCallbackKeepsTerminalClean(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.SetStatusCallback(newLogger(false))

	stdout, stderr := captureConsole(t, func() { runCancelledEventLoop(t, el) })

	requireNoConsoleOutput(t, stdout, stderr)
}

// TestEventLoopWithoutStatusCallbackFallsBackToStderr pins the default for
// loops built outside trace setup: lifecycle lines still reach stderr, and
// stdout stays reserved for machine-readable output.
func TestEventLoopWithoutStatusCallbackFallsBackToStderr(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.SetStatusCallback(nil)

	stdout, stderr := captureConsole(t, func() { runCancelledEventLoop(t, el) })

	if stdout != "" {
		t.Fatalf("stdout = %q, want it empty", stdout)
	}
	if !strings.Contains(stderr, "Stopping event loop") {
		t.Fatalf("stderr = %q, want the stop line", stderr)
	}
}

func syscallPairNames(syscalls ...string) []string {
	names := make([]string, 0, 2*len(syscalls))
	for _, syscall := range syscalls {
		names = append(names, "sys_enter_"+syscall, "sys_exit_"+syscall)
	}
	return names
}

// TestAttachSyscallProbesRoutesSkipsThroughLogger covers the per-tracepoint
// attach warnings that used to go straight to stderr during TUI attach. They
// must reach only the injected logger, and the failed probe must stay in the
// manager with its error so States() can surface it in the TUI.
func TestAttachSyscallProbesRoutesSkipsThroughLogger(t *testing.T) {
	attacher := &fakeProbeAttacher{
		prog: &fakeProbeProgram{err: errors.New("no such tracepoint")},
	}
	rec := &lineRecorder{}

	var mgr *probemanager.Manager
	stdout, stderr := captureConsole(t, func() {
		m, err := attachSyscallProbes(attacher, nil, syscallPairNames("openat"), rec.log)
		if err != nil {
			t.Errorf("attachSyscallProbes() error = %v, want per-probe failures to be non-fatal", err)
			return
		}
		mgr = m
		states := m.States()
		if len(states) != 1 || states[0].Active || !strings.Contains(states[0].Error, "no such tracepoint") {
			t.Errorf("States() = %+v, want one inactive openat probe carrying its attach error", states)
		}
	})
	if mgr != nil {
		if err := mgr.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}

	requireNoConsoleOutput(t, stdout, stderr)
	logged := rec.joined()
	if !strings.Contains(logged, "skipping tracepoint for openat") || !strings.Contains(logged, "no such tracepoint") {
		t.Fatalf("logged = %q, want the skipped openat tracepoint and its cause", logged)
	}
}

// TestAttachSyscallProbesSilentOnSuccess is the negative case: a clean attach
// logs nothing and skips only what the selector excludes.
func TestAttachSyscallProbesSilentOnSuccess(t *testing.T) {
	attacher := &fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}}
	onlyOpenat := func(tp string) bool { return strings.HasSuffix(tp, "_openat") }

	var active []string
	stdout, stderr := captureConsole(t, func() {
		mgr, err := attachSyscallProbes(attacher, onlyOpenat, syscallPairNames("openat", "read"), failOnLog(t))
		if err != nil {
			t.Errorf("attachSyscallProbes() error = %v", err)
			return
		}
		for _, state := range mgr.States() {
			if state.Active {
				active = append(active, state.Syscall)
			}
		}
		if err := mgr.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	requireNoConsoleOutput(t, stdout, stderr)
	if len(active) != 1 || active[0] != "openat" {
		t.Fatalf("active probes = %q, want only openat", active)
	}
}
