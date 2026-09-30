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

// runProgramWithSignal runs the real Bubble Tea event loop (production
// wiring via newProgram, plus forwardHangup) on m and delivers sig to this
// process once the loop is up. It returns what Run returned.
func runProgramWithSignal(t *testing.T, m *Model, sig syscall.Signal) error {
	t.Helper()
	input, inputW := io.Pipe()
	t.Cleanup(func() { _ = inputW.Close() })
	program := newProgram(m, tea.WithInput(input), tea.WithOutput(io.Discard), tea.WithWindowSize(100, 30))
	stopHangup := forwardHangup(program.Send)
	defer stopHangup()

	// Until Bubble Tea has registered its own SIGINT/SIGTERM handler the
	// default action would kill the test binary, so hold a registration of
	// our own; signals sent before Run is up land there and are retried.
	sink := make(chan os.Signal, 64)
	signal.Notify(sink, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sink)

	var finished atomic.Bool
	go func() {
		for !finished.Load() {
			_ = syscall.Kill(os.Getpid(), sig)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	defer finished.Store(true)

	_, err := program.Run()
	return err
}

func TestSignalsFinaliseRecordingInTheRealProgram(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			if sig == syscall.SIGHUP && signal.Ignored(syscall.SIGHUP) {
				t.Skip("SIGHUP is ignored by the test process (nohup); forwardHangup rightly stays out")
			}
			m, path := modelRecordingTo(t)
			done := make(chan error, 1)
			go func() { done <- runProgramWithSignal(t, m, sig) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run() = %v, want a clean exit through the quit path", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("program did not exit after the signal")
			}
			if !m.quitting {
				t.Fatal("the model never saw the quit request")
			}
			requireFinalisedRecording(t, path)
		})
	}
}

func TestForwardHangupStaysOutWhenSIGHUPIsIgnored(t *testing.T) {
	var sent atomic.Int32
	stop := forwardHangupFor(func(tea.Msg) { sent.Add(1) }, true)
	defer stop()
	// SIGHUP would kill the test binary if a handler were (wrongly) absent
	// and the disposition default; hold one so a wrongly installed relay is
	// the only thing that could send.
	sink := make(chan os.Signal, 1)
	signal.Notify(sink, syscall.SIGHUP)
	defer signal.Stop(sink)
	_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
	select {
	case <-sink:
	case <-time.After(5 * time.Second):
		t.Fatal("test SIGHUP was not delivered")
	}
	time.Sleep(50 * time.Millisecond)
	if n := sent.Load(); n != 0 {
		t.Fatalf("relay sent %d messages although SIGHUP is ignored", n)
	}
}

func TestRelayQuitRequestsStopsCleanly(t *testing.T) {
	ch := make(chan os.Signal, 1)
	got := make(chan tea.Msg, 4)
	unregistered := false
	stop := relayQuitRequests(ch, func(m tea.Msg) { got <- m }, func() { unregistered = true })

	ch <- syscall.SIGHUP
	select {
	case m := <-got:
		if _, ok := m.(tea.QuitMsg); !ok {
			t.Fatalf("relay sent %T, want tea.QuitMsg", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not forward the signal")
	}
	stop()
	if !unregistered {
		t.Fatal("stop did not unregister the signal handler")
	}
	ch <- syscall.SIGHUP
	time.Sleep(20 * time.Millisecond)
	if len(got) != 0 {
		t.Fatal("relay sent a message after stop returned")
	}
}
