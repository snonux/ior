package parquet

import (
	"errors"
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

func TestRecorderFailsOnQueueOverflow(t *testing.T) {
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
	if err := recorder.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("first Record() error = %v", err)
	}

	<-writer.started

	if err := recorder.Record(testStreamRow(2, "write", false), 0); err != nil {
		t.Fatalf("second Record() error = %v", err)
	}
	if err := recorder.Record(testStreamRow(3, "openat", false), 0); !errors.Is(err, ErrRecorderQueueFull) {
		t.Fatalf("third Record() error = %v, want %v", err, ErrRecorderQueueFull)
	}

	writer.releaseWrites()

	if err := recorder.Stop(); !errors.Is(err, ErrRecorderQueueFull) {
		t.Fatalf("Stop() error = %v, want %v", err, ErrRecorderQueueFull)
	}

	status := recorder.Status()
	if status.Active {
		t.Fatalf("Status().Active = true, want false")
	}
	if !errors.Is(status.LastError, ErrRecorderQueueFull) {
		t.Fatalf("Status().LastError = %v, want %v", status.LastError, ErrRecorderQueueFull)
	}
	if !writer.aborted.Load() {
		t.Fatalf("expected recorder failure path to abort the backing writer")
	}
}

func testStreamRow(seq uint64, syscall string, isError bool) streamrow.Row {
	return streamrow.Row{
		Seq:        seq,
		TimeNs:     seq * 10,
		Syscall:    syscall,
		Comm:       "ior-test",
		PID:        100 + uint32(seq),
		TID:        200 + uint32(seq),
		FileName:   "/tmp/file",
		DurationNs: seq + 1,
		GapNs:      seq + 2,
		Bytes:      seq + 3,
		RetVal:     int64(seq),
		IsError:    isError,
		FD:         int32(seq),
	}
}

type blockingWriter struct {
	started chan struct{}
	release chan struct{}

	startOnce   sync.Once
	releaseOnce sync.Once

	aborted atomic.Bool
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockingWriter) WriteRows([]Record) error {
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
