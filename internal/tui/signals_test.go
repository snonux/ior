package tui

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/streamrow"

	tea "charm.land/bubbletea/v2"
)

// modelRecordingTo returns a model whose real Parquet recorder is active on a
// path in a temp dir, one row already recorded, plus that final path.
func modelRecordingTo(t *testing.T) (*Model, string) {
	t.Helper()
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	rec := parquet.NewRecorder(parquet.RecorderConfig{})
	m.runtime.recorder = rec
	path := filepath.Join(t.TempDir(), "rec.parquet")
	if err := rec.Start(path, parquet.StartOptions{}); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if err := rec.Record(streamrow.Row{}, 0); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	t.Cleanup(func() { _ = rec.Stop() })
	return m, path
}

// requireFinalisedRecording fails unless path is a non-empty published file
// and no ior-*.tmp orphan is left next to it: the two outcomes the bug flipped.
func requireFinalisedRecording(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("recording %s was not published: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("recording %s is empty", path)
	}
	orphans, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp"))
	if len(orphans) != 0 {
		t.Fatalf("orphan temp files left behind: %v", orphans)
	}
}

func TestSignalQuitFilterConvertsQuitAndInterruptWhileRunning(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	for _, msg := range []tea.Msg{tea.QuitMsg{}, tea.InterruptMsg{}} {
		if got := signalQuitFilter(m, msg); got != (signalQuitMsg{}) {
			t.Errorf("filter(%T) = %#v, want signalQuitMsg", msg, got)
		}
	}
}

// Negative cases: the model's own shutdown-complete tea.Quit, a second signal
// during a stuck shutdown, other messages and foreign models are untouched.
func TestSignalQuitFilterPassesEverythingElseThrough(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.quitting = true
	for _, msg := range []tea.Msg{tea.QuitMsg{}, tea.InterruptMsg{}} {
		if got := signalQuitFilter(m, msg); got != msg {
			t.Errorf("quitting model: filter(%T) = %#v, want it unchanged", msg, got)
		}
	}
	m.quitting = false
	key := tea.KeyPressMsg{Code: 'x'}
	if got := signalQuitFilter(m, key); got != tea.Msg(key) {
		t.Errorf("filter(key) = %#v, want it unchanged", got)
	}
	if got := signalQuitFilter(nil, tea.QuitMsg{}); got != (tea.QuitMsg{}) {
		t.Errorf("filter(foreign model) = %#v, want QuitMsg unchanged", got)
	}
}

func TestSignalQuitMsgFinalisesActiveRecordingThroughQuitPath(t *testing.T) {
	m, path := modelRecordingTo(t)

	next, cmd := m.Update(signalQuitMsg{})
	if !next.(*Model).quitting {
		t.Fatal("signalQuitMsg did not start the shutdown")
	}
	if cmd == nil {
		t.Fatal("signalQuitMsg returned no command; tea.Quit would never be dispatched")
	}
	requireFinalisedRecording(t, path)

	// A repeated signal while shutting down must not restart the shutdown.
	if _, cmd := m.Update(signalQuitMsg{}); cmd != nil {
		t.Fatal("second signalQuitMsg produced a command while already quitting")
	}
}

// TestSafetyNetFinalisesRecordingWhenTheModelWasBypassed covers exits that
// never reach Update (panic, second signal cutting the shutdown short).
func TestSafetyNetFinalisesRecordingWhenTheModelWasBypassed(t *testing.T) {
	m, path := modelRecordingTo(t)
	original := runTeaProgram
	t.Cleanup(func() { runTeaProgram = original })
	runTeaProgram = func(m *Model) (tea.Model, error) { return m, nil }

	if err := runProgram(m); err != nil {
		t.Fatalf("runProgram() = %v", err)
	}
	requireFinalisedRecording(t, path)
}

func TestSafetyNetKeepsTheRunErrorAndReportsAStopFailure(t *testing.T) {
	runErr := errors.New("boom")
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	if got := finaliseRecording(m, runErr); got != runErr {
		t.Fatalf("no recorder: finaliseRecording = %v, want the run error unchanged", got)
	}

	stopErr := errors.New("disk full")
	m.runtime.recorder = &stopFailingRecorder{stopErr: stopErr}
	got := finaliseRecording(m, runErr)
	if !errors.Is(got, runErr) || !errors.Is(got, stopErr) {
		t.Fatalf("finaliseRecording = %v, want both the run and the stop error", got)
	}
	if got := finaliseRecording(m, nil); !errors.Is(got, stopErr) {
		t.Fatalf("finaliseRecording(nil) = %v, want the stop error", got)
	}
}

type stopFailingRecorder struct {
	failedRecordingController
	stopErr error
}

func (r *stopFailingRecorder) Status() parquet.Status { return parquet.Status{Active: true} }
func (r *stopFailingRecorder) Stop() error            { return r.stopErr }

// holdSignals keeps a registration for the termination signals for the whole
// test, so a signal sent while no watcher is registered (before the program is
// up, or after it returned) is swallowed instead of killing the test binary.
func holdSignals(t *testing.T) {
	t.Helper()
	sink := make(chan os.Signal, 64)
	signal.Notify(sink, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(sink) })
}

// startWatchedProgram runs the real Bubble Tea event loop with the production
// wiring (newProgram + watchTerminationSignals + runWithWatcher) on model and returns a channel that
// yields what Run returned.
func startWatchedProgram(t *testing.T, model tea.Model) <-chan error {
	t.Helper()
	holdSignals(t)
	input, inputW := io.Pipe()
	t.Cleanup(func() { _ = inputW.Close() })
	program := newProgram(model, tea.WithInput(input), tea.WithOutput(io.Discard), tea.WithWindowSize(100, 30))
	// Registered before Run starts, so a signal sent right after this returns
	// is already handled by the watcher.
	var hooks watcherHooks
	if m, ok := model.(*Model); ok {
		hooks.publishRecording = modelRecordingPublisher(m)
	}
	watcher := watchTerminationSignals(program, hooks)
	t.Cleanup(watcher.stop) // idempotent; covers a test that never gets to run
	done := make(chan error, 1)
	go func() {
		_, err := runWithWatcher(program, watcher)
		watcher.stop() // as runWatchedProgram does: no timer or handler outlives Run
		done <- err
	}()
	return done
}

func sendSignal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("kill(%v) = %v", sig, err)
	}
}

func waitForRun(t *testing.T, done <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(20 * time.Second):
		t.Fatalf("program did not exit: %s", what)
		return nil
	}
}

func TestSignalsFinaliseRecordingInTheRealProgram(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			if sig == syscall.SIGHUP && signal.Ignored(syscall.SIGHUP) {
				t.Skip("SIGHUP is ignored by the test process (nohup); the watcher rightly stays out")
			}
			m, path := modelRecordingTo(t)
			done := startWatchedProgram(t, m)
			sendSignal(t, sig)
			if err := waitForRun(t, done, "single "+sig.String()); err != nil {
				t.Fatalf("Run() = %v, want a clean exit through the quit path", err)
			}
			requireFinalisedRecording(t, path)
		})
	}
}

// hungShutdownModel returns a model on the dashboard whose trace shutdown never
// completes (a BPF teardown stuck in the kernel), a recorder that is active,
// and a channel closed once the shutdown has begun.
func hungShutdownModel(t *testing.T) (*Model, string, <-chan struct{}) {
	t.Helper()
	m, path := modelRecordingTo(t)
	m.router.showDashboard()
	m.attaching = false
	m.tracer.shutdownReporter = runtime.NewTraceShutdownReporter() // never Complete()d
	began := make(chan struct{})
	m.tracer.traceStop = func() { close(began) }
	return m, path, began
}

// shortSignalTiming shrinks the debounce and grace so the tests need not wait
// seconds, and reports hardExit calls instead of exiting the test binary.
func shortSignalTiming(t *testing.T) *atomic.Int32 {
	t.Helper()
	window, grace, exit := repeatSignalWindow, forceExitGrace, hardExit
	var exits atomic.Int32
	// The grace stays well above what a forced exit needs to unwind Run, so a
	// loaded machine does not make the hardExit backstop fire first.
	repeatSignalWindow, forceExitGrace = 100*time.Millisecond, 500*time.Millisecond
	hardExit = func() { exits.Add(1) }
	t.Cleanup(func() { repeatSignalWindow, forceExitGrace, hardExit = window, grace, exit })
	return &exits
}

// TestSecondSignalEndsAHungShutdown is the escape hatch: with a shutdown that
// never completes, the first signal starts it (and is not enough), a signal
// after the debounce window aborts it, Run returns errShutdownForced, and the
// recording is still published by the safety net.
func TestSecondSignalEndsAHungShutdown(t *testing.T) {
	pairs := []struct{ first, second syscall.Signal }{
		{syscall.SIGTERM, syscall.SIGTERM},
		{syscall.SIGINT, syscall.SIGINT},
		{syscall.SIGTERM, syscall.SIGINT},
		{syscall.SIGHUP, syscall.SIGTERM},
	}
	for _, p := range pairs {
		t.Run(p.first.String()+"_then_"+p.second.String(), func(t *testing.T) {
			if p.first == syscall.SIGHUP && signal.Ignored(syscall.SIGHUP) {
				t.Skip("SIGHUP is ignored by the test process (nohup)")
			}
			exits := shortSignalTiming(t)
			m, path, began := hungShutdownModel(t)
			done := startWatchedProgram(t, m)

			sendSignal(t, p.first)
			select {
			case <-began:
			case <-time.After(20 * time.Second):
				t.Fatal("the first signal did not start the shutdown")
			}
			select {
			case err := <-done:
				t.Fatalf("Run returned after one signal (%v) although the shutdown is hung", err)
			case <-time.After(3 * repeatSignalWindow):
			}

			sendSignal(t, p.second)
			if err := waitForRun(t, done, "second signal during a hung shutdown"); !errors.Is(err, errShutdownForced) {
				t.Fatalf("Run() = %v, want errShutdownForced", err)
			}
			// The safety net publishes what the model finalised on the first signal.
			if err := finaliseRecording(m, nil); err != nil {
				t.Fatalf("finaliseRecording() = %v", err)
			}
			requireFinalisedRecording(t, path)
			time.Sleep(2 * forceExitGrace)
			if n := exits.Load(); n != 0 {
				t.Fatalf("hardExit called %d times although Run returned", n)
			}
		})
	}
}

// A repeat inside the debounce window (systemd's SIGTERM+SIGHUP pair) is the
// same request and must not abort a teardown that is still healthy.
func TestRepeatSignalInsideTheWindowDoesNotAbort(t *testing.T) {
	shortSignalTiming(t)
	repeatSignalWindow = 30 * time.Second
	m, _, began := hungShutdownModel(t)
	done := startWatchedProgram(t, m)

	sendSignal(t, syscall.SIGTERM)
	awaitSignal(t, began, "the shutdown to begin")
	sendSignal(t, syscall.SIGINT)
	select {
	case err := <-done:
		t.Fatalf("Run returned (%v) after a repeat inside the window", err)
	case <-time.After(500 * time.Millisecond):
	}
	// Let the shutdown finish normally so the program (and the test) end.
	m.tracer.shutdownReporter.Complete()
	if err := waitForRun(t, done, "completed shutdown"); err != nil {
		t.Fatalf("Run() = %v, want a clean exit once the shutdown completed", err)
	}
}

// wedgedModel blocks in Update on the quit request, like a recorder Stop stuck
// on a dead disk: Program.Kill cannot make Run return then.
type wedgedModel struct {
	entered chan struct{}
	release chan struct{}
}

func (w *wedgedModel) Init() tea.Cmd  { return nil }
func (w *wedgedModel) View() tea.View { return tea.NewView("") }
func (w *wedgedModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(signalQuitMsg); ok {
		close(w.entered)
		<-w.release
	}
	return w, nil
}

func TestForcedExitFallsBackToHardExitWhenUpdateIsWedged(t *testing.T) {
	exits := shortSignalTiming(t)
	w := &wedgedModel{entered: make(chan struct{}), release: make(chan struct{})}
	done := startWatchedProgram(t, w)

	sendSignal(t, syscall.SIGTERM)
	awaitSignal(t, w.entered, "Update to take the quit request")
	time.Sleep(2 * repeatSignalWindow)
	sendSignal(t, syscall.SIGTERM)

	deadline := time.Now().Add(10 * time.Second)
	for exits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exits.Load() != 1 {
		t.Fatalf("hardExit calls = %d, want 1 after the grace period", exits.Load())
	}
	close(w.release)
	_ = waitForRun(t, done, "released wedged model")
}

func TestCtrlCWhileShuttingDownAbortsAndOtherKeysAreIgnored(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.quitting = true

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
	if cmd != nil || next.(*Model).lastErr != nil {
		t.Fatalf("plain key while quitting: cmd=%v lastErr=%v, want ignored", cmd, next.(*Model).lastErr)
	}

	next, cmd = m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if cmd == nil {
		t.Fatal("ctrl+c while quitting returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("ctrl+c command = %T, want tea.QuitMsg", cmd())
	}
	if got := signalQuitFilter(next, tea.QuitMsg{}); got != (tea.QuitMsg{}) {
		t.Fatalf("filter converted the abort's QuitMsg: %#v", got)
	}
	if err := finalModelError(next); !errors.Is(err, errShutdownForced) {
		t.Fatalf("finalModelError = %v, want errShutdownForced", err)
	}
}

// A recorder that cannot be stopped on the signal path must not vanish
// silently: the exit is reported (and non-zero through the run error).
func TestSignalQuitReportsARecorderStopFailure(t *testing.T) {
	m, path := modelRecordingTo(t)
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	next, cmd := m.Update(signalQuitMsg{})
	if !next.(*Model).quitting || cmd == nil {
		t.Fatal("a failing recorder must not keep the process from shutting down")
	}
	original := runTeaProgram
	t.Cleanup(func() { runTeaProgram = original })
	runTeaProgram = func(m *Model) (tea.Model, error) { return m, nil }
	err := runProgram(m)
	if err == nil {
		t.Fatal("runProgram() = nil, the lost recording went unreported")
	}
}

func TestSignalQuitWithAHealthyRecorderReportsNothing(t *testing.T) {
	m, path := modelRecordingTo(t)
	next, _ := m.Update(signalQuitMsg{})
	if err := next.(*Model).lastErr; err != nil {
		t.Fatalf("lastErr = %v after a healthy stop", err)
	}
	original := runTeaProgram
	t.Cleanup(func() { runTeaProgram = original })
	runTeaProgram = func(m *Model) (tea.Model, error) { return m, nil }
	if err := runProgram(m); err != nil {
		t.Fatalf("runProgram() = %v", err)
	}
	requireFinalisedRecording(t, path)
}

func TestTerminationSignalsHonourInheritedSIGHUPIgnore(t *testing.T) {
	has := func(sigs []os.Signal, want os.Signal) bool {
		for _, s := range sigs {
			if s == want {
				return true
			}
		}
		return false
	}
	if got := terminationSignals(false); !has(got, syscall.SIGHUP) || !has(got, syscall.SIGINT) || !has(got, syscall.SIGTERM) {
		t.Fatalf("terminationSignals(false) = %v, want INT, TERM and HUP", got)
	}
	got := terminationSignals(true)
	if has(got, syscall.SIGHUP) || !has(got, syscall.SIGINT) || !has(got, syscall.SIGTERM) {
		t.Fatalf("terminationSignals(true) = %v, want INT and TERM only", got)
	}
}

func TestRelayTerminationSignalsQuitsThenForcesOnceAfterTheWindow(t *testing.T) {
	window := repeatSignalWindow
	// Generous: the two values below are queued together and the relay must
	// look at both within the window even if it is descheduled in between.
	repeatSignalWindow = 400 * time.Millisecond
	t.Cleanup(func() { repeatSignalWindow = window })

	ch := make(chan os.Signal, 8)
	var quits, forces atomic.Int32
	unregistered := false
	stop := relayTerminationSignals(ch, nil, func() { quits.Add(1) }, func() { forces.Add(1) }, func() { unregistered = true })

	ch <- syscall.SIGTERM
	ch <- syscall.SIGHUP // inside the window: same request
	waitFor(t, func() bool { return quits.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if forces.Load() != 0 || quits.Load() != 1 {
		t.Fatalf("inside the window: quits=%d forces=%d, want 1/0", quits.Load(), forces.Load())
	}
	time.Sleep(repeatSignalWindow) // now the window since the first signal is over
	ch <- syscall.SIGTERM
	ch <- syscall.SIGTERM // a third one changes nothing
	waitFor(t, func() bool { return forces.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if forces.Load() != 1 || quits.Load() != 1 {
		t.Fatalf("after the window: quits=%d forces=%d, want 1/1", quits.Load(), forces.Load())
	}
	stop()
	if !unregistered {
		t.Fatal("stop did not unregister the signal handler")
	}
	ch <- syscall.SIGTERM
	time.Sleep(20 * time.Millisecond)
	if forces.Load() != 1 || quits.Load() != 1 {
		t.Fatal("relay acted after stop returned")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
