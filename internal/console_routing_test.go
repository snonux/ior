package internal

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
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

// --- setup warnings: one policy for non-fatal setup degradations ---

// failingSchedAttacher makes both sched probes fail to attach.
func failingSchedAttacher() *fakeProbeAttacher {
	return &fakeProbeAttacher{prog: &fakeProbeProgram{err: errors.New("no such tracepoint")}}
}

// collectSetupDegradations reproduces the two setup degradations trace setup
// can hit without a live kernel - a sched probe that fails to attach and a
// BPF object without the drop-counter map (the nil module) - through the same
// sinks setupTraceInfraWithEventLoop wires, and returns the resulting loop
// ready to run.
func collectSetupDegradations(t *testing.T, logln func(...any)) *eventLoop {
	t.Helper()
	warnings := &setupWarnings{}
	var el *eventLoop
	stdout, stderr := captureConsole(t, func() {
		attachProcessExecProbe(failingSchedAttacher(), bpfSetupLog{
			status: failOnLog(t), warn: warnings.add, teardown: failOnLog(t),
		})
		el = mustNewEventLoop(t, eventLoopConfig{})
		attachRingbufDropCounter(el, nil, warnings.add)
		wireEventLoopLogging(el, logln, warnings)
	})
	// Nothing may be printed while setup runs: in TUI mode Bubble Tea is
	// already drawing, and these used to go to stderr on every trace start.
	requireNoConsoleOutput(t, stdout, stderr)
	return el
}

func requireSetupDegradations(t *testing.T, got string) {
	t.Helper()
	for _, want := range []string{"skipping sched_process_exec probe", "Ring-buffer drop counter unavailable"} {
		if !strings.Contains(got, want) {
			t.Fatalf("replayed warnings = %q, want them to contain %q", got, want)
		}
	}
}

// TestSetupDegradationsBecomeTUIWarningRows is the TUI half: with a silent
// logln and a warning sink wired (makeTUIEventLoopConfigurer), both
// degradations surface through warningCb - where they turn into warning rows -
// and nothing reaches the terminal.
func TestSetupDegradationsBecomeTUIWarningRows(t *testing.T) {
	el := collectSetupDegradations(t, newLogger(false))
	rows := &lineRecorder{}
	el.SetWarningCallback(func(message string) { rows.log(message) })

	stdout, stderr := captureConsole(t, func() { runCancelledEventLoop(t, el) })

	requireNoConsoleOutput(t, stdout, stderr)
	if n := len(rows.lines()); n != 2 {
		t.Fatalf("warning rows = %q, want exactly the 2 setup degradations", rows.lines())
	}
	requireSetupDegradations(t, rows.joined())
}

// TestSetupDegradationsReachStderrHeadless is the headless half: no warning
// sink is wired, so the replay falls back to stderr and stdout stays clean.
func TestSetupDegradationsReachStderrHeadless(t *testing.T) {
	el := collectSetupDegradations(t, newLogger(true))

	stdout, stderr := captureConsole(t, func() { runCancelledEventLoop(t, el) })

	if stdout != "" {
		t.Fatalf("stdout = %q, want it empty", stdout)
	}
	requireSetupDegradations(t, stderr)
}

// TestPendingWarningsReplayOnce guards against a double replay, and pins that
// an empty setup produces no warning at all.
func TestPendingWarningsReplayOnce(t *testing.T) {
	warnings := &setupWarnings{}
	warnings.add() // an empty message is not a warning
	warnings.add("drop counter", "unavailable")
	el := mustNewEventLoop(t, eventLoopConfig{})
	rows := &lineRecorder{}
	el.SetWarningCallback(func(message string) { rows.log(message) })
	wireEventLoopLogging(el, failOnLog(t), warnings)

	el.flushPendingWarnings()
	el.flushPendingWarnings()

	if got := rows.lines(); len(got) != 1 || got[0] != "drop counter unavailable" {
		t.Fatalf("replayed = %q, want the one warning exactly once", got)
	}
	if left := warnings.drain(); len(left) != 0 {
		t.Fatalf("collector still holds %q after wiring, want it drained", left)
	}
}

// --- nil sinks must neither panic nor drop a message ---

func TestAttachSchedProbeWithZeroSetupLogFallsBackToStderr(t *testing.T) {
	stdout, stderr := captureConsole(t, func() {
		attachProcessExecProbe(failingSchedAttacher(), bpfSetupLog{})
	})
	if stdout != "" || !strings.Contains(stderr, "skipping sched_process_exec probe") {
		t.Fatalf("stdout=%q stderr=%q, want the skipped probe on stderr", stdout, stderr)
	}

	link := &fakeProbeLink{err: errors.New("detach boom")}
	release := attachProcessExitProbe(&fakeProbeAttacher{prog: &fakeProbeProgram{link: link}}, bpfSetupLog{})
	_, stderr = captureConsole(t, release)
	if !strings.Contains(stderr, "detach boom") {
		t.Fatalf("stderr = %q, want the detach error", stderr)
	}
}

func TestAttachSyscallProbesWithNilLoggerFallsBackToStderr(t *testing.T) {
	stdout, stderr := captureConsole(t, func() {
		mgr, err := attachSyscallProbes(failingSchedAttacher(), nil, syscallPairNames("openat"), nil)
		if err != nil {
			t.Errorf("attachSyscallProbes() error = %v", err)
			return
		}
		if err := mgr.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if stdout != "" || !strings.Contains(stderr, "skipping tracepoint for openat") {
		t.Fatalf("stdout=%q stderr=%q, want the skipped tracepoint on stderr", stdout, stderr)
	}
}

// --- trace setup wiring ---

// TestSetupTraceInfraWiresConsoleSinks pins how setupTraceInfraWithEventLoop
// connects the sinks exercised above. The function cannot run unprivileged
// (setupBPFModule fails on rlimit first), so, like the ordering tests in
// ior_setup_test.go, this checks its structure: BPF setup receives the
// mode-dependent logln as status, the setup-warning collector as warn and the
// always-on logger as teardown; the event-loop factory receives the same
// collector; and the loop is wired to logln and the collected warnings right
// after it is stored, before the start signal.
func TestSetupTraceInfraWiresConsoleSinks(t *testing.T) {
	decl, _ := parseInternalFunction(t, "ior.go", "setupTraceInfraWithEventLoop")

	bpfCalls := callsNamed(decl, "setupBPFModule")
	if len(bpfCalls) != 1 || len(bpfCalls[0].Args) != 3 {
		t.Fatal("shared trace setup must call setupBPFModule(parentCtx, cfg, bpfSetupLog{...}) once")
	}
	literal, ok := bpfCalls[0].Args[2].(*ast.CompositeLit)
	if !ok || !isIdentifier(literal.Type, "bpfSetupLog") {
		t.Fatal("setupBPFModule's log argument must be a bpfSetupLog literal")
	}
	wantSinks := map[string]string{"status": "logln", "warn": "warnSetup", "teardown": "logTeardown"}
	gotSinks := map[string]string{}
	for _, element := range literal.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok {
			t.Fatal("bpfSetupLog literal must use keyed fields")
		}
		key, _ := kv.Key.(*ast.Ident)
		value, _ := kv.Value.(*ast.Ident)
		if key != nil && value != nil {
			gotSinks[key.Name] = value.Name
		}
	}
	if fmt.Sprint(gotSinks) != fmt.Sprint(wantSinks) {
		t.Fatalf("bpfSetupLog sinks = %v, want %v", gotSinks, wantSinks)
	}

	if !hasAssignment(decl, "warnSetup", "warnings", "add") {
		t.Fatal("warnSetup must be the setup-warning collector's add method")
	}

	wireIndex := -1
	for i, statement := range decl.Body.List {
		if expr, ok := statement.(*ast.ExprStmt); ok &&
			isBareCallWithIdentifierArgs(expr.X, "wireEventLoopLogging", "el", "logln", "warnings") {
			wireIndex = i
		}
	}
	if wireIndex < 1 || !isEventLoopFieldAssignment(decl.Body.List[wireIndex-1]) {
		t.Fatal("wireEventLoopLogging(el, logln, warnings) must directly follow `infra.el = el`")
	}
	if signal := firstCallPosition(decl, "signalTraceStarted"); !signal.IsValid() || decl.Body.List[wireIndex].Pos() > signal {
		t.Fatal("event-loop logging must be wired before the trace-started signal")
	}
}

// hasAssignment reports whether decl's body contains `name := receiver.method`.
func hasAssignment(decl *ast.FuncDecl, name, receiver, method string) bool {
	for _, statement := range decl.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || !identifiersMatch(assignment.Lhs, name) || len(assignment.Rhs) != 1 {
			continue
		}
		selector, ok := assignment.Rhs[0].(*ast.SelectorExpr)
		if ok && selector.Sel.Name == method && isIdentifier(selector.X, receiver) {
			return true
		}
	}
	return false
}
