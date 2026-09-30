package parquet

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/streamrow"
)

func TestRecorderRoundTrip(t *testing.T) {
	recorder := NewRecorder(RecorderConfig{
		QueueCapacity: 8,
		BatchSize:     2,
		FlushInterval: time.Hour,
	})

	path := filepath.Join(t.TempDir(), "session")
	if err := recorder.Start(path, StartOptions{Metadata: FileMetadata{Mode: "tui"}}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	rows := []streamrow.Row{
		testStreamRow(1, "read", false),
		testStreamRow(2, "write", false),
		testStreamRow(3, "openat", true),
	}
	epochs := []uint64{0, 0, 3}

	for i := range rows {
		if err := recorder.Record(rows[i], epochs[i]); err != nil {
			t.Fatalf("Record(%d) error = %v", i, err)
		}
	}

	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	status := recorder.Status()
	if status.Active {
		t.Fatalf("Status().Active = true, want false")
	}
	if status.RowsWritten != 3 {
		t.Fatalf("Status().RowsWritten = %d, want 3", status.RowsWritten)
	}
	if status.RowsDropped != 0 {
		t.Fatalf("Status().RowsDropped = %d, want 0", status.RowsDropped)
	}
	if status.LastError != nil {
		t.Fatalf("Status().LastError = %v, want nil", status.LastError)
	}
	if status.TempPath != "" {
		t.Fatalf("Status().TempPath = %q, want empty after successful stop", status.TempPath)
	}

	want := []Record{
		RecordFromStream(rows[0], epochs[0]),
		RecordFromStream(rows[1], epochs[1]),
		RecordFromStream(rows[2], epochs[2]),
	}
	got := readAllRecords(t, status.Path)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("records mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestRecorderShedsRowsOnQueueOverflowInsteadOfAborting(t *testing.T) {
	writer := newBlockingWriter()
	recorder := NewRecorder(RecorderConfig{
		QueueCapacity: 1,
		BatchSize:     1,
		FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) {
			return writer, nil
		},
	})

	if err := recorder.Start("ignored", StartOptions{}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	// The first row fills the queue and is picked up by the session
	// goroutine, which blocks inside WriteRows (batch size 1).
	if err := recorder.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("first Record() error = %v", err)
	}
	<-writer.started

	// The session goroutine is blocked in WriteRows, so the second row keeps
	// the single queue slot occupied and further rows must be shed, not
	// fatal: the session stays active and drops are counted.
	if err := recorder.Record(testStreamRow(2, "write", false), 0); err != nil {
		t.Fatalf("second Record() error = %v", err)
	}
	for i := 3; i <= 4; i++ {
		err := recorder.Record(testStreamRow(uint64(i), "openat", false), 0)
		if !errors.Is(err, ErrRecorderQueueFull) {
			t.Fatalf("Record(%d) error = %v, want %v", i, err, ErrRecorderQueueFull)
		}
	}

	live := recorder.Status()
	if !live.Active {
		t.Fatalf("Status().Active = false, want session to survive queue overflow")
	}
	if live.RowsDropped != 2 {
		t.Fatalf("Status().RowsDropped = %d, want 2 while session is active", live.RowsDropped)
	}

	// Releasing the writer lets the session drain; Stop must gracefully
	// flush the surviving rows and finalize the recording, not abort it.
	writer.releaseWrites()
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop() error = %v, want nil", err)
	}

	status := recorder.Status()
	if status.Active {
		t.Fatalf("Status().Active = true, want false")
	}
	if status.LastError != nil {
		t.Fatalf("Status().LastError = %v, want nil", status.LastError)
	}
	if status.RowsDropped != 2 {
		t.Fatalf("Status().RowsDropped = %d, want 2 after stop", status.RowsDropped)
	}
	if status.RowsWritten != 2 {
		t.Fatalf("Status().RowsWritten = %d, want 2", status.RowsWritten)
	}
	if writer.aborted.Load() {
		t.Fatalf("queue overflow must not abort the backing writer")
	}
	if got := writer.written.Load(); got != 2 {
		t.Fatalf("writer rows = %d, want 2", got)
	}
}

// TestRecorderStressQueueSaturation reproduces the audit's total-abort
// scenario (queue saturation under sustained load, AUDIT-REPORT.md M14 /
// domain-09 Y1) with concurrent producers hammering a blocked writer. It
// asserts the shed-mode invariants: every attempted row is either written
// or counted as dropped, accounting is exact, and the session finalizes
// the partial recording instead of aborting it.
func TestRecorderStressQueueSaturation(t *testing.T) {
	writer := newBlockingWriter()
	recorder := NewRecorder(RecorderConfig{
		QueueCapacity: 16,
		BatchSize:     16,
		FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) {
			return writer, nil
		},
	})

	if err := recorder.Start("ignored", StartOptions{}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	const producers = 8
	const rowsPerProducer = 250
	const attempted = producers * rowsPerProducer

	var accepted, shed atomic.Uint64
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < rowsPerProducer; i++ {
				err := recorder.Record(testStreamRow(uint64(p*rowsPerProducer+i+1), "read", false), 0)
				switch {
				case err == nil:
					accepted.Add(1)
				case errors.Is(err, ErrRecorderQueueFull):
					shed.Add(1)
				default:
					t.Errorf("Record() error = %v, want nil or %v", err, ErrRecorderQueueFull)
				}
			}
		}(p)
	}
	wg.Wait()

	// The writer is still blocked, so at most one batch plus one queue
	// worth of rows can be in flight; the saturation sheds must have been
	// observed and counted.
	writer.releaseWrites()
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop() error = %v, want nil", err)
	}

	status := recorder.Status()
	if status.Active {
		t.Fatalf("Status().Active = true, want false")
	}
	if status.LastError != nil {
		t.Fatalf("Status().LastError = %v, want nil", status.LastError)
	}
	if writer.aborted.Load() {
		t.Fatalf("queue saturation must not abort the backing writer")
	}

	acceptedCount := accepted.Load()
	shedCount := shed.Load()
	if shedCount == 0 {
		t.Fatalf("stress run observed no overflow sheds; test no longer reproduces queue saturation")
	}
	if acceptedCount+shedCount != attempted {
		t.Fatalf("accepted(%d)+shed(%d) = %d, want %d", acceptedCount, shedCount, acceptedCount+shedCount, attempted)
	}
	if status.RowsDropped != shedCount {
		t.Fatalf("Status().RowsDropped = %d, want %d", status.RowsDropped, shedCount)
	}
	if status.RowsWritten != acceptedCount {
		t.Fatalf("Status().RowsWritten = %d, want %d (every accepted row must be persisted)", status.RowsWritten, acceptedCount)
	}
	if status.RowsWritten != writer.written.Load() {
		t.Fatalf("Status().RowsWritten = %d, want writer rows %d", status.RowsWritten, writer.written.Load())
	}
	if status.RowsWritten+status.RowsDropped != attempted {
		t.Fatalf("RowsWritten(%d)+RowsDropped(%d) = %d, want %d", status.RowsWritten, status.RowsDropped, status.RowsWritten+status.RowsDropped, attempted)
	}
}

func TestRecorderStopReportsTerminalErrorOnceOnRepeatedCalls(t *testing.T) {
	// Queue overflow no longer aborts a session, so a writer failure stands
	// in for the terminal error a finished session may carry. Repeated Stop
	// calls must all return promptly (the done channel is already closed),
	// but only the first reports the failure: a failure is reported once.
	terminalErr := errors.New("parquet writer failed")
	recorder := NewRecorder(RecorderConfig{})
	session := newRecordingSession(1)
	session.doneErr = terminalErr
	close(session.doneC)

	recorder.mu.Lock()
	recorder.active = session
	recorder.status = Status{
		Active:    true,
		LastError: terminalErr,
	}
	recorder.mu.Unlock()

	if err := recorder.Stop(); !errors.Is(err, terminalErr) {
		t.Fatalf("first Stop() error = %v, want %v", err, terminalErr)
	}
	if err := recorder.Stop(); err != nil {
		t.Fatalf("second Stop() error = %v, want nil (already reported)", err)
	}
}

func testStreamRow(seq uint64, syscall string, isError bool) streamrow.Row {
	return streamrow.Row{
		Seq:               seq,
		TimeNs:            seq * 10,
		Syscall:           syscall,
		Family:            "FS",
		Comm:              "ior-test",
		PID:               100 + uint32(seq),
		TID:               200 + uint32(seq),
		FileName:          "/tmp/file",
		DurationNs:        seq + 1,
		GapNs:             seq + 2,
		Bytes:             seq + 3,
		AddressSpaceBytes: seq + 4,
		Nfds:              int32(seq + 5),
		TimeoutNs:         int64(seq + 6),
		RetVal:            int64(seq),
		IsError:           isError,
		FD:                int32(seq),
	}
}

type blockingWriter struct {
	started chan struct{}
	release chan struct{}

	startOnce   sync.Once
	releaseOnce sync.Once

	written atomic.Uint64
	aborted atomic.Bool
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockingWriter) WriteRows(rows []Record) error {
	w.written.Add(uint64(len(rows)))
	w.startOnce.Do(func() { close(w.started) })
	<-w.release
	return nil
}

func (w *blockingWriter) Close() error {
	return nil
}

func (w *blockingWriter) Abort() error {
	w.aborted.Store(true)
	w.releaseWrites()
	return nil
}

func (w *blockingWriter) FinalPath() string {
	return "ignored.parquet"
}

func (w *blockingWriter) TempPath() string {
	return "ignored.parquet.tmp"
}

func (w *blockingWriter) releaseWrites() {
	w.releaseOnce.Do(func() { close(w.release) })
}

// TestRecorderStatusPathFollowsSuffixedPublish pins that when the requested
// path is already taken, the recording is published under a "-N" name and
// Status().Path names the file that actually holds it.
func TestRecorderStatusPathFollowsSuffixedPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.parquet")
	taken := []byte("someone else's file")
	if err := os.WriteFile(path, taken, 0o644); err != nil {
		t.Fatal(err)
	}

	recorder := NewRecorder(RecorderConfig{QueueCapacity: 4, BatchSize: 2, FlushInterval: time.Hour})
	if err := recorder.Start(path, StartOptions{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := recorder.Status().Path; got != path {
		t.Fatalf("Status().Path while recording = %q, want the requested %q", got, path)
	}
	if err := recorder.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	want := filepath.Join(dir, "session-1.parquet")
	if got := recorder.Status().Path; got != want {
		t.Fatalf("Status().Path after Stop = %q, want %q", got, want)
	}
	if got, _ := os.ReadFile(path); string(got) != string(taken) {
		t.Errorf("existing file was clobbered: %q", got)
	}
	if rows := readAllRecords(t, want); len(rows) != 1 || rows[0].Seq != 1 {
		t.Errorf("published file rows = %+v, want the one recorded row", rows)
	}
}
