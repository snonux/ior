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

// TestRecorderStopAfterFailureTakenReturnsNil checks that Stop does not
// re-report a failure that was already handed out, by TakeFailure or by an
// earlier Stop, while a not-yet-taken failure is still returned.
func TestRecorderStopAfterFailureTakenReturnsNil(t *testing.T) {
	writeErr := errors.New("disk full")

	r := newFailingRecorder(writeErr, 1)
	failRecording(t, r)
	if err := r.TakeFailure(); !errors.Is(err, writeErr) {
		t.Fatalf("TakeFailure() = %v, want %v", err, writeErr)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() after TakeFailure = %v, want nil", err)
	}

	r = newFailingRecorder(writeErr, 1)
	failRecording(t, r)
	if err := r.Stop(); !errors.Is(err, writeErr) {
		t.Fatalf("first Stop() = %v, want %v", err, writeErr)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop() = %v, want nil", err)
	}
	if st := r.Status(); !errors.Is(st.LastError, writeErr) {
		t.Fatalf("Status().LastError = %v, want it kept as %v", st.LastError, writeErr)
	}
}

// abortBlockingWriter fails every write and blocks in Abort until released,
// holding a self-aborting session between its failure and finishSession.
type abortBlockingWriter struct {
	failingWriter
	aborting chan struct{}
	release  chan struct{}
}

func (w abortBlockingWriter) Abort() error {
	close(w.aborting)
	<-w.release
	return nil
}

// TestRecorderStopDuringSelfAbortReportsOnce covers Stop arriving before
// finishSession of a session that is aborting on its own (write failed,
// writer held in Abort): Stop must return the failure and TakeFailure must
// not hand it out a second time. The narrower interleaving - finishSession
// running inside Stop, between its snapshot and its stop mark - is forced by
// TestRecorderFinishDuringStopReportsOnce.
func TestRecorderStopDuringSelfAbortReportsOnce(t *testing.T) {
	writeErr := errors.New("disk full")
	w := abortBlockingWriter{
		failingWriter: failingWriter{err: writeErr},
		aborting:      make(chan struct{}),
		release:       make(chan struct{}),
	}
	r := NewRecorder(RecorderConfig{
		BatchSize:     1,
		FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) {
			return w, nil
		},
	})
	mustStart(t, r)
	if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	<-w.aborting // the session failed and is blocked before finishSession

	r.mu.RLock()
	session := r.active
	r.mu.RUnlock()
	stopErr := make(chan error, 1)
	go func() { stopErr <- r.Stop() }()
	waitStopRequested(t, session)
	if err := r.TakeFailure(); err != nil {
		t.Fatalf("TakeFailure() while the session is finishing = %v, want nil", err)
	}
	close(w.release)

	if err := <-stopErr; !errors.Is(err, writeErr) {
		t.Fatalf("Stop() = %v, want %v", err, writeErr)
	}
	if err := r.TakeFailure(); err != nil {
		t.Fatalf("TakeFailure() after Stop returned the failure = %v, want nil", err)
	}
}

// TestRecorderStopRacingSelfAbortStress races Stop against a session that
// fails its first write on its own. Whichever wins, the failure is reported
// exactly once: through Stop, never again through TakeFailure.
func TestRecorderStopRacingSelfAbortStress(t *testing.T) {
	writeErr := errors.New("disk full")
	// The race window is tiny: the pre-fix code failed about once in ~10k
	// iterations without -race (much sooner with it), so run many; this is
	// a probabilistic guard next to the hook-driven
	// TestRecorderFinishDuringStopReportsOnce.
	iterations := 10000
	if testing.Short() {
		iterations = 1000
	}
	for i := 0; i < iterations; i++ {
		r := newFailingRecorder(writeErr, 1)
		mustStart(t, r)
		if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
			t.Fatalf("iteration %d: Record() error = %v", i, err)
		}
		taken := make(chan error, 1)
		go func() { taken <- r.TakeFailure() }()
		stopErr := r.Stop()
		lateTake := r.TakeFailure()
		reports := 0
		for _, err := range []error{stopErr, <-taken, lateTake} {
			if errors.Is(err, writeErr) {
				reports++
			}
		}
		if reports != 1 {
			t.Fatalf("iteration %d: failure reported %d times (Stop=%v), want exactly once", i, reports, stopErr)
		}
	}
}

// setStopUnlockedHook installs hook as Stop's test seam for this test.
func setStopUnlockedHook(t *testing.T, hook func()) {
	t.Helper()
	stopUnlockedHook = hook
	t.Cleanup(func() { stopUnlockedHook = nil })
}

// startAbortBlockedRecorder returns a recorder whose writer fails every
// write and blocks in Abort until w.release is closed, with a recording
// started. batchSize 1 makes the first Record fail the session on its own;
// a large one defers the failure to Stop's final flush.
func startAbortBlockedRecorder(t *testing.T, batchSize int) (*Recorder, abortBlockingWriter, error) {
	t.Helper()
	writeErr := errors.New("disk full")
	w := abortBlockingWriter{
		failingWriter: failingWriter{err: writeErr},
		aborting:      make(chan struct{}),
		release:       make(chan struct{}),
	}
	r := NewRecorder(RecorderConfig{
		BatchSize:     batchSize,
		FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) {
			return w, nil
		},
	})
	mustStart(t, r)
	if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	return r, w, writeErr
}

// TestRecorderFinishDuringStopReportsOnce forces the interleaving that
// used to report a failure twice: the self-aborting session runs
// finishSession to completion after Stop has seen it active and released
// r.mu. Stop marks the request before unlocking, so finishSession sees it and
// the failure goes to Stop only. (With the mark taken after unlocking, the
// session finishes unmarked here, publishes the failure as untaken, and
// TakeFailure hands it out again - every time.)
func TestRecorderFinishDuringStopReportsOnce(t *testing.T) {
	r, w, writeErr := startAbortBlockedRecorder(t, 1)
	<-w.aborting // the session failed and is blocked before finishSession
	setStopUnlockedHook(t, func() {
		close(w.release)
		waitInactive(t, r) // finishSession has run
	})

	if err := r.Stop(); !errors.Is(err, writeErr) {
		t.Fatalf("Stop() = %v, want %v", err, writeErr)
	}
	if err := r.TakeFailure(); err != nil {
		t.Fatalf("TakeFailure() after Stop returned the failure = %v, want nil", err)
	}
}

// TestRecorderConcurrentStopsReportFailureOnce has two Stop calls reach the
// same active session; the failure (Stop's final flush fails) must be
// returned by exactly one of them, and not handed out by TakeFailure.
func TestRecorderConcurrentStopsReportFailureOnce(t *testing.T) {
	r, w, writeErr := startAbortBlockedRecorder(t, 1024)
	entered := make(chan struct{}, 2)
	setStopUnlockedHook(t, func() { entered <- struct{}{} })

	results := make(chan error, 2)
	for range 2 {
		go func() { results <- r.Stop() }()
	}
	// Both Stops have seen the session active. It cannot finish before
	// w.release is closed: its final flush fails and it then blocks in Abort.
	<-entered
	<-entered
	close(w.release)

	reports := 0
	for range 2 {
		if err := <-results; errors.Is(err, writeErr) {
			reports++
		} else if err != nil {
			t.Fatalf("Stop() = %v, want nil or %v", err, writeErr)
		}
	}
	if reports != 1 {
		t.Fatalf("failure returned by %d Stop calls, want exactly 1", reports)
	}
	if err := r.TakeFailure(); err != nil {
		t.Fatalf("TakeFailure() = %v, want nil", err)
	}
}

// waitInactive waits until the recorder's session has finished.
func waitInactive(t *testing.T, r *Recorder) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.Status().Active {
		if time.Now().After(deadline) {
			t.Fatalf("session did not finish in time")
		}
		time.Sleep(time.Millisecond)
	}
}

// waitStopRequested waits until Stop has marked session as stop-requested.
func waitStopRequested(t *testing.T, session *recordingSession) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !session.wasStopRequested() {
		if time.Now().After(deadline) {
			t.Fatalf("Stop did not mark the session in time")
		}
		time.Sleep(time.Millisecond)
	}
}
