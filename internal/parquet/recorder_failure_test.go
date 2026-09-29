package parquet

import (
	"errors"
	"testing"
	"time"
)

// failingWriter rejects every batch with err, standing in for a disk error.
type failingWriter struct{ err error }

func (w failingWriter) WriteRows([]Record) error { return w.err }
func (failingWriter) Close() error               { return nil }
func (failingWriter) Abort() error               { return nil }
func (failingWriter) FinalPath() string          { return "ignored.parquet" }
func (failingWriter) TempPath() string           { return "ignored.parquet.tmp" }

// newFailingRecorder returns a recorder whose recordings fail their first
// batch write (batch size 1, so the first recorded row triggers it) with err.
func newFailingRecorder(err error, batchSize int) *Recorder {
	return NewRecorder(RecorderConfig{
		BatchSize:     batchSize,
		FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) {
			return failingWriter{err: err}, nil
		},
	})
}

// waitSessionDead waits until the recorder's session has published an error.
func waitSessionDead(t *testing.T, r *Recorder) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st := r.Status(); !st.Active && st.LastError != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("recording did not fail in time: %+v", r.Status())
		}
		time.Sleep(time.Millisecond)
	}
}

func mustStart(t *testing.T, r *Recorder) {
	t.Helper()
	if err := r.Start("ignored", StartOptions{}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
}

// failRecording starts a recording, records one row and waits for the write
// failure to kill the session.
func failRecording(t *testing.T, r *Recorder) {
	t.Helper()
	mustStart(t, r)
	if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record() on a live recording error = %v, want nil", err)
	}
	waitSessionDead(t, r)
}

func TestRecorderTakeFailureReportsEachFailureOnce(t *testing.T) {
	writeErr := errors.New("disk full")
	r := newFailingRecorder(writeErr, 1)

	for rec := 1; rec <= 2; rec++ {
		mustStart(t, r)
		if err := r.TakeFailure(); err != nil {
			t.Fatalf("recording %d: TakeFailure() while active = %v, want nil", rec, err)
		}
		if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
			t.Fatalf("recording %d: Record() error = %v, want nil", rec, err)
		}
		waitSessionDead(t, r)

		// Record keeps returning the dead recording's error...
		for i := 0; i < 2; i++ {
			if err := r.Record(testStreamRow(2, "read", false), 0); !errors.Is(err, writeErr) {
				t.Fatalf("recording %d: Record() after failure = %v, want %v", rec, err, writeErr)
			}
		}
		// ...but TakeFailure hands it out exactly once per recording.
		if err := r.TakeFailure(); !errors.Is(err, writeErr) {
			t.Fatalf("recording %d: first TakeFailure() = %v, want %v", rec, err, writeErr)
		}
		if err := r.TakeFailure(); err != nil {
			t.Fatalf("recording %d: second TakeFailure() = %v, want nil", rec, err)
		}
	}
}

func TestRecorderTakeFailureNilWithoutFailure(t *testing.T) {
	var nilRecorder *Recorder
	if err := nilRecorder.TakeFailure(); err != nil {
		t.Fatalf("nil recorder TakeFailure() = %v, want nil", err)
	}

	r := NewRecorder(RecorderConfig{
		BatchSize:     1,
		FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) {
			w := newBlockingWriter()
			w.releaseWrites()
			return w, nil
		},
	})
	if err := r.TakeFailure(); err != nil {
		t.Fatalf("never-started TakeFailure() = %v, want nil", err)
	}
	mustStart(t, r)
	if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := r.TakeFailure(); err != nil {
		t.Fatalf("TakeFailure() after clean stop = %v, want nil", err)
	}
}

// TestRecorderStopReturnedFailureIsTaken covers both ways Stop hands a
// failure to its caller: a recording that already died, and a flush that
// fails while Stop drains it. TakeFailure must not report either again.
func TestRecorderStopReturnedFailureIsTaken(t *testing.T) {
	writeErr := errors.New("disk full")

	t.Run("already dead", func(t *testing.T) {
		r := newFailingRecorder(writeErr, 1)
		failRecording(t, r)
		if err := r.Stop(); !errors.Is(err, writeErr) {
			t.Fatalf("Stop() = %v, want %v", err, writeErr)
		}
		if err := r.TakeFailure(); err != nil {
			t.Fatalf("TakeFailure() after Stop returned it = %v, want nil", err)
		}
	})

	t.Run("fails while stopping", func(t *testing.T) {
		// A large batch keeps rows buffered until Stop's final flush fails.
		r := newFailingRecorder(writeErr, 1024)
		mustStart(t, r)
		if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
		if err := r.Stop(); !errors.Is(err, writeErr) {
			t.Fatalf("Stop() = %v, want %v", err, writeErr)
		}
		if err := r.TakeFailure(); err != nil {
			t.Fatalf("TakeFailure() after Stop returned it = %v, want nil", err)
		}
		if err := r.Record(testStreamRow(2, "read", false), 0); !errors.Is(err, writeErr) {
			t.Fatalf("Record() after failed stop = %v, want the LastError %v", err, writeErr)
		}
	})
}

// TestRecorderFirstDropSentinelPerRecording checks that the first shed row
// of each recording returns ErrRecorderStartedDropping (still matching
// ErrRecorderQueueFull), later sheds plain ErrRecorderQueueFull, and that a
// Stop -> Start with no rows in between re-arms the sentinel.
func TestRecorderFirstDropSentinelPerRecording(t *testing.T) {
	var current *blockingWriter
	r := NewRecorder(RecorderConfig{
		QueueCapacity: 1,
		BatchSize:     1,
		FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) {
			current = newBlockingWriter()
			return current, nil
		},
	})

	for rec := 1; rec <= 2; rec++ {
		mustStart(t, r)
		// Row 1 blocks the session goroutine in WriteRows; row 2 fills the
		// single queue slot; further rows are shed.
		if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
			t.Fatalf("recording %d: Record(1) error = %v", rec, err)
		}
		<-current.started
		if err := r.Record(testStreamRow(2, "read", false), 0); err != nil {
			t.Fatalf("recording %d: Record(2) error = %v", rec, err)
		}
		err := r.Record(testStreamRow(3, "read", false), 0)
		if !errors.Is(err, ErrRecorderStartedDropping) || !errors.Is(err, ErrRecorderQueueFull) {
			t.Fatalf("recording %d: first shed = %v, want %v wrapping %v", rec, err, ErrRecorderStartedDropping, ErrRecorderQueueFull)
		}
		err = r.Record(testStreamRow(4, "read", false), 0)
		if !errors.Is(err, ErrRecorderQueueFull) || errors.Is(err, ErrRecorderStartedDropping) {
			t.Fatalf("recording %d: second shed = %v, want plain %v", rec, err, ErrRecorderQueueFull)
		}
		current.releaseWrites()
		if err := r.Stop(); err != nil {
			t.Fatalf("recording %d: Stop() error = %v", rec, err)
		}
	}
}
