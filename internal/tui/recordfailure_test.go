package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ior/internal/parquet"
	"ior/internal/streamrow"

	tea "charm.land/bubbletea/v2"
)

// failedRecordingController is an idle RecordingController whose previous
// recording failed. It mirrors parquet.Recorder's semantics for that state
// (tested for real in package parquet): Record keeps returning the failure
// (the dead recording's LastError), TakeFailure hands it out exactly once and
// nil afterwards, and Stop/Status report an inactive recorder.
type failedRecordingController struct {
	failure error
	takes   int
}

func (f *failedRecordingController) Record(streamrow.Row, uint64) error { return f.failure }
func (f *failedRecordingController) Start(string, parquet.StartOptions) error {
	return nil
}
func (f *failedRecordingController) Stop() error            { return nil }
func (f *failedRecordingController) Status() parquet.Status { return parquet.Status{} }
func (f *failedRecordingController) TakeFailure() error {
	f.takes++
	err := f.failure
	f.failure = nil
	return err
}

func pressRecordKey(t *testing.T, m *Model) *Model {
	t.Helper()
	next, _ := m.Update(tea.KeyPressMsg{Code: 'R', Text: "R"})
	return next.(*Model)
}

// TestRecordModalShowsUnreportedPreviousFailure checks that opening the
// record modal claims a previous recording's failure nobody reported yet
// (Start would discard it) and shows it once; reopening shows no error.
func TestRecordModalShowsUnreportedPreviousFailure(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	recorder := &failedRecordingController{failure: errors.New("disk full")}
	m.runtime.recorder = recorder

	m = pressRecordKey(t, m)
	view := m.recordModal.View(120, 30)
	if !m.recordModal.Visible() || !strings.Contains(view, "previous recording failed: disk full") {
		t.Fatalf("record modal should show the previous failure, got:\n%s", view)
	}

	m.recordModal = m.recordModal.Close()
	m = pressRecordKey(t, m)
	if view := m.recordModal.View(120, 30); strings.Contains(view, "Error:") {
		t.Fatalf("reopened record modal should show no error, got:\n%s", view)
	}
	if recorder.takes != 2 {
		t.Fatalf("TakeFailure calls = %d, want one per modal open (2)", recorder.takes)
	}
}

// TestRecordModalWithoutPreviousFailureShowsNoError covers the common case:
// an idle recorder with nothing to report, and no recorder at all.
func TestRecordModalWithoutPreviousFailureShowsNoError(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	m = pressRecordKey(t, m)
	if view := m.recordModal.View(120, 30); !m.recordModal.Visible() || strings.Contains(view, "Error:") {
		t.Fatalf("record modal should open without an error, got:\n%s", view)
	}
	if err := takePreviousRecordingFailure(nil); err != nil {
		t.Fatalf("takePreviousRecordingFailure(nil) = %v, want nil", err)
	}
}
