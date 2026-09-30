package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ior/internal/runtime"
	"ior/internal/streamrow"

	tea "charm.land/bubbletea/v2"
)

// newModelWithSelfAbortedRecording returns a model whose recorder holds the
// state of a recording that aborted on its own (disk full) on an idle target:
// inactive, failure untaken, and no further event to report it in the stream.
// failedRecordingController mirrors parquet.Recorder's semantics for that
// state (the real ones are tested in package parquet).
func newModelWithSelfAbortedRecording(t *testing.T, cause error) (*Model, *failedRecordingController) {
	t.Helper()
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	recorder := &failedRecordingController{failure: cause}
	m.runtime.recorder = recorder
	return m, recorder
}

// TestSafetyNetReportsSelfAbortedRecording is the xp2 review finding: a
// recording that died with no later event, never reported and never seen in
// the record modal, used to be lost on exit (recorderStop skipped the inactive
// recorder). The exit error now names the cause, exactly once.
func TestSafetyNetReportsSelfAbortedRecording(t *testing.T) {
	cause := errors.New("disk full")
	m, _ := newModelWithSelfAbortedRecording(t, cause)

	err := finaliseRecording(m, nil)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "finalising Parquet recording") {
		t.Fatalf("finaliseRecording() = %v, want the recording's failure", err)
	}
	if err := finaliseRecording(m, nil); err != nil {
		t.Fatalf("second finaliseRecording() = %v, want the failure reported only once", err)
	}
}

// TestQuitKeepsFailureAlreadyReported pins exactly-once: a failure a warning
// row (or the modal) already delivered is marked taken and the quit must not
// report it again.
func TestQuitKeepsFailureAlreadyReported(t *testing.T) {
	m, recorder := newModelWithSelfAbortedRecording(t, errors.New("disk full"))
	view := m.runtime.beginSession()
	view.Recorder().(runtime.WarningRecorder).RecordWarning(streamrow.Row{}, 0, runtime.RecorderWarningText)
	if got := warningRows(m.runtime); len(got) != 1 {
		t.Fatalf("warning rows = %q, want the failure shown once", got)
	}

	if err := finaliseRecording(m, nil); err != nil {
		t.Fatalf("finaliseRecording() = %v, want nil for an already reported failure", err)
	}
	next, _, _ := m.quitWithBestEffortCleanup()
	if err := finalModelError(next); err != nil {
		t.Fatalf("quit reported %v again", err)
	}
	if recorder.takes != 3 {
		t.Fatalf("TakeFailure calls = %d, want 3 (warning, safety net, quit)", recorder.takes)
	}
}

// TestQuitWithHealthyIdleRecorderReportsNothing: no recording ever failed.
func TestQuitWithHealthyIdleRecorderReportsNothing(t *testing.T) {
	m, _ := newModelWithSelfAbortedRecording(t, nil)
	if err := finaliseRecording(m, nil); err != nil {
		t.Fatalf("finaliseRecording() = %v, want nil", err)
	}
	next, _, _ := m.quitWithBestEffortCleanup()
	if err := finalModelError(next); err != nil {
		t.Fatalf("quit reported %v, want nil", err)
	}
}

// TestQuitPathsReportSelfAbortedRecording drives every quit entry point that
// has to surface the failure through the exit status.
func TestQuitPathsReportSelfAbortedRecording(t *testing.T) {
	cause := errors.New("disk full")
	t.Run("signal quit", func(t *testing.T) {
		m, _ := newModelWithSelfAbortedRecording(t, cause)
		next, cmd := m.Update(signalQuitMsg{})
		if cmd == nil {
			t.Fatal("signal quit did not start the shutdown")
		}
		if err := finalModelError(next); !errors.Is(err, cause) {
			t.Fatalf("finalModelError() = %v, want %v", err, cause)
		}
	})
	t.Run("best-effort quit", func(t *testing.T) {
		m, _ := newModelWithSelfAbortedRecording(t, cause)
		next, _, _ := m.quitWithBestEffortCleanup()
		if err := finalModelError(next); !errors.Is(err, cause) {
			t.Fatalf("finalModelError() = %v, want %v", err, cause)
		}
	})
	t.Run("dashboard q shows it, second q leaves once", func(t *testing.T) {
		m, recorder := newModelWithSelfAbortedRecording(t, cause)
		next, _ := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
		m = next.(*Model)
		if !errors.Is(m.lastErr, cause) || m.errorKind != errorScreenRecoverable || m.quitting {
			t.Fatalf("after q: lastErr=%v kind=%v quitting=%v, want the failure on a recoverable error screen", m.lastErr, m.errorKind, m.quitting)
		}
		shown := m.lastErr
		next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
		updated := assertQuits(t, next, cmd)
		if updated.lastErr != shown {
			t.Fatalf("lastErr = %v, want the displayed error unchanged", updated.lastErr)
		}
		if recorder.takes != 2 {
			t.Fatalf("TakeFailure calls = %d, want 2 (one claim, one empty)", recorder.takes)
		}
	})
	t.Run("signal watcher publish", func(t *testing.T) {
		m, _ := newModelWithSelfAbortedRecording(t, cause)
		publish := modelRecordingPublisher(m)
		if err := publish(); !errors.Is(err, cause) {
			t.Fatalf("publish() = %v, want %v", err, cause)
		}
		if err := publish(); err != nil {
			t.Fatalf("second publish() = %v, want nil", err)
		}
	})
}
