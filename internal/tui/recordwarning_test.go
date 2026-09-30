package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"ior/internal/runtime"
	"ior/internal/streamrow"

	tea "charm.land/bubbletea/v2"
)

// warningRows returns the warning rows currently in the bindings' stream.
func warningRows(r *runtimeBindings) []string {
	var msgs []string
	for _, row := range r.streamBuffer.Snapshot() {
		if row.Syscall == "warning" {
			msgs = append(msgs, row.FileName)
		}
	}
	return msgs
}

func newFailedRecorderBindings(failure error) (*runtimeBindings, *failedRecordingController) {
	r := newRuntimeBindings()
	recorder := &failedRecordingController{failure: failure}
	r.recorder = recorder
	return r, recorder
}

// TestSessionRecorderWarnsWhileCurrent is the positive case: a current
// session claims the failure and its warning row lands in the stream.
func TestSessionRecorderWarnsWhileCurrent(t *testing.T) {
	r, recorder := newFailedRecorderBindings(errors.New("disk full"))
	view := r.beginSession()

	view.Recorder().(runtime.WarningRecorder).RecordWarning(streamrow.Row{}, 0, runtime.RecorderWarningText)

	if got := warningRows(r); len(got) != 1 || !strings.Contains(got[0], "disk full") {
		t.Fatalf("warning rows = %q, want one naming the failure", got)
	}
	if recorder.takes != 1 {
		t.Fatalf("TakeFailure calls = %d, want 1", recorder.takes)
	}
}

// TestRetiredSessionClaimsNoFailure is the task xp2 regression: a session
// that a stop has already retired must not consume the failure. Before the
// fix TakeFailure was ungated, so the failure was marked reported while the
// session's warning row was dropped, and neither the next session nor the
// record modal ever saw it.
func TestRetiredSessionClaimsNoFailure(t *testing.T) {
	r, recorder := newFailedRecorderBindings(errors.New("disk full"))
	view := r.beginSession()
	rec := view.Recorder().(runtime.WarningRecorder)
	view.end() // the stop landing between Record and TakeFailure

	rec.RecordWarning(streamrow.Row{}, 0, func(runtime.RowRecorder, error) string {
		t.Error("describe ran for a retired session")
		return ""
	})
	if err := rec.TakeFailure(); err != nil {
		t.Fatalf("retired session TakeFailure() = %v, want nil", err)
	}
	if got := warningRows(r); len(got) != 0 {
		t.Fatalf("retired session pushed warnings %q", got)
	}
	if recorder.takes != 0 {
		t.Fatalf("retired session claimed the failure (%d takes)", recorder.takes)
	}

	// The failure is still there for whoever can show it: the record modal
	// reads the TUI-owned recorder directly...
	if err := takePreviousRecordingFailure(r.Recorder()); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("modal claim = %v, want the failure the retired session left", err)
	}
}

// TestNextSessionReportsFailureLeftByRetiredSession checks the other consumer:
// a later session reports exactly once what the retired one left unclaimed.
func TestNextSessionReportsFailureLeftByRetiredSession(t *testing.T) {
	r, _ := newFailedRecorderBindings(errors.New("disk full"))
	old := r.beginSession()
	old.end()
	old.Recorder().(runtime.WarningRecorder).RecordWarning(streamrow.Row{}, 0, runtime.RecorderWarningText)

	next := r.beginSession().Recorder().(runtime.WarningRecorder)
	next.RecordWarning(streamrow.Row{}, 0, runtime.RecorderWarningText)
	next.RecordWarning(streamrow.Row{}, 0, runtime.RecorderWarningText)

	if got := warningRows(r); len(got) != 1 {
		t.Fatalf("warning rows = %q, want the failure reported exactly once", got)
	}
}

// TestEndSessionWaitsForAnInFlightWarning replays the lost-warning window
// through the real gate: the stop arrives while the session is between
// claiming the failure and pushing its row. endSession must wait for that
// step, so the row lands (and is attributed to the session that claimed it)
// instead of being dropped after the claim.
func TestEndSessionWaitsForAnInFlightWarning(t *testing.T) {
	r, _ := newFailedRecorderBindings(errors.New("disk full"))
	view := r.beginSession()
	rec := view.Recorder().(runtime.WarningRecorder)

	claimed := make(chan struct{})
	release := make(chan struct{})
	recorded := make(chan struct{})
	go func() {
		defer close(recorded)
		rec.RecordWarning(streamrow.Row{}, 0, func(rec runtime.RowRecorder, result error) string {
			message := runtime.RecorderWarningText(rec, result) // the claim
			close(claimed)
			<-release // the stop lands here
			return message
		})
	}()

	<-claimed
	ended := make(chan struct{})
	go func() {
		view.end()
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("endSession returned while a warning was still being published")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-recorded
	<-ended

	if got := warningRows(r); len(got) != 1 || !strings.Contains(got[0], "disk full") {
		t.Fatalf("warning rows = %q, want the claimed failure's row", got)
	}
}

// TestSessionRecorderRecordWarningSilentWithoutNews pins the quiet path: no
// message means no row, and an idle result leaves the failure alone.
func TestSessionRecorderRecordWarningSilentWithoutNews(t *testing.T) {
	r := newRuntimeBindings() // real idle parquet recorder: ErrRecorderNotActive
	view := r.beginSession()
	view.Recorder().(runtime.WarningRecorder).RecordWarning(streamrow.Row{}, 0, runtime.RecorderWarningText)
	if got := warningRows(r); len(got) != 0 {
		t.Fatalf("idle recorder pushed warnings %q", got)
	}
}

// TestSessionRecorderClaimsNothingWithoutAWarningSink is the delivery-side
// twin of the retired-session case: with no stream buffer (or sequencer) to
// take the row, describe must not run, because its TakeFailure would mark the
// failure reported with nowhere to show it. The failure stays with the
// recorder for the record modal and the quit path.
func TestSessionRecorderClaimsNothingWithoutAWarningSink(t *testing.T) {
	for name, strip := range map[string]func(*runtimeBindings){
		"no stream buffer": func(r *runtimeBindings) { r.streamBuffer = nil },
		"no sequencer":     func(r *runtimeBindings) { r.streamSeq = nil },
	} {
		t.Run(name, func(t *testing.T) {
			r, recorder := newFailedRecorderBindings(errors.New("disk full"))
			strip(r)
			view := r.beginSession()

			view.Recorder().(runtime.WarningRecorder).RecordWarning(streamrow.Row{}, 0, func(runtime.RowRecorder, error) string {
				t.Error("describe ran although the warning cannot be delivered")
				return ""
			})
			view.Recorder().(runtime.WarningRecorder).RecordWarning(streamrow.Row{}, 0, runtime.RecorderWarningText)

			if recorder.takes != 0 {
				t.Fatalf("failure claimed %d times with no sink to show it", recorder.takes)
			}
			if err := takePreviousRecordingFailure(r.Recorder()); err == nil || !strings.Contains(err.Error(), "disk full") {
				t.Fatalf("modal claim = %v, want the failure left unclaimed", err)
			}
		})
	}
}

// TestQuitFromDashboardErrorScreenReportsStopFailureOnce drives the real
// path: dashboard q with a recorder that cannot finalise puts the Stop error
// on a recoverable error screen; quitting from there must not report it a
// second time (Stop hands a failure out once), nor lose it.
func TestQuitFromDashboardErrorScreenReportsStopFailureOnce(t *testing.T) {
	m := newRecorderStopErrorScreen(t)
	shown := m.lastErr

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := assertQuits(t, next, cmd)

	if updated.lastErr != shown {
		t.Fatalf("lastErr = %v, want the displayed error unchanged (%v)", updated.lastErr, shown)
	}
}

// TestBestEffortQuitKeepsStopFailureWithoutAnotherError covers the quit paths
// that have no error on screen (startup picker, attach): the Stop failure
// alone becomes the program's error, and a clean Stop leaves none.
func TestBestEffortQuitKeepsStopFailureWithoutAnotherError(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	armRecorderStopFailure(t, m)

	next, cmd, _ := m.quitWithBestEffortCleanup()
	updated := next.(*Model)
	if cmd == nil || !updated.quitting {
		t.Fatal("best-effort quit did not begin the shutdown")
	}
	if err := finalModelError(updated); err == nil || !strings.Contains(err.Error(), "finalising Parquet recording") {
		t.Fatalf("finalModelError() = %v, want the Stop failure", err)
	}

	clean := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	next, _, _ = clean.quitWithBestEffortCleanup()
	if err := finalModelError(next); err != nil {
		t.Fatalf("clean quit reported %v, want nil", err)
	}
}
