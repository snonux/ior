package parquet

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	parquetgo "github.com/parquet-go/parquet-go"
)

func TestWriterRoundTripAndFinalize(t *testing.T) {
	dir := t.TempDir()
	writer, err := NewWriter(filepath.Join(dir, "trace"), WriterConfig{}, FileMetadata{
		Hostname:          "test-host",
		StartedAtUnixNano: 1234,
		Mode:              "tui",
	})
	if err != nil {
		t.Fatalf("NewWriter() error = %v", err)
	}

	rows := []Record{
		{
			Seq:         1,
			TimeNS:      10,
			GapNS:       2,
			LatencyNS:   5,
			Comm:        "cat",
			PID:         11,
			TID:         12,
			Syscall:     "read",
			FD:          3,
			Ret:         42,
			Bytes:       42,
			File:        "/tmp/input",
			IsError:     false,
			FilterEpoch: 7,
		},
		{
			Seq:         2,
			TimeNS:      20,
			GapNS:       3,
			LatencyNS:   6,
			Comm:        "cp",
			PID:         21,
			TID:         22,
			Syscall:     "write",
			FD:          4,
			Ret:         -1,
			Bytes:       99,
			File:        "/tmp/output",
			IsError:     true,
			FilterEpoch: 8,
		},
	}

	if err := writer.WriteRows(rows); err != nil {
		t.Fatalf("WriteRows() error = %v", err)
	}
	if _, err := os.Stat(writer.TempPath()); err != nil {
		t.Fatalf("Stat(%q) error = %v, want temp file present", writer.TempPath(), err)
	}
	if _, err := os.Stat(writer.FinalPath()); !os.IsNotExist(err) {
		t.Fatalf("Stat(%q) error = %v, want not-exist before Close", writer.FinalPath(), err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := os.Stat(writer.TempPath()); !os.IsNotExist(err) {
		t.Fatalf("Stat(%q) error = %v, want temp removed after Close", writer.TempPath(), err)
	}
	if _, err := os.Stat(writer.FinalPath()); err != nil {
		t.Fatalf("Stat(%q) error = %v, want finalized parquet file", writer.FinalPath(), err)
	}

	got := readAllRecords(t, writer.FinalPath())
	if !reflect.DeepEqual(got, rows) {
		t.Fatalf("records mismatch\n got: %+v\nwant: %+v", got, rows)
	}
}

func readAllRecords(t *testing.T, path string) []Record {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", path, err)
	}
	defer func() { _ = f.Close() }()

	reader := parquetgo.NewGenericReader[Record](f)
	defer func() { _ = reader.Close() }()

	var rows []Record
	buf := make([]Record, 4)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			rows = append(rows, buf[:n]...)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return rows
		}
		t.Fatalf("Read() error = %v", err)
	}
}

// TestWritersAimedAtOnePathKeepEveryRecording is the regression for two
// recordings that resolve to the same name (default names are only accurate to
// the second): they used to share one ".tmp" and the later rename replaced the
// earlier file. Now each has its own temp file and the later publish lands
// under a "-1" name, reported by FinalPath. This is the policy for ior's
// generated default names (NewAutoNamedWriter).
func TestAutoNamedWritersAimedAtOnePathKeepEveryRecording(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.parquet")
	rowsA := []Record{{Seq: 1, Comm: "a", Syscall: "read"}}
	rowsB := []Record{{Seq: 2, Comm: "b", Syscall: "write"}}

	a, err := NewAutoNamedWriter(path, WriterConfig{}, FileMetadata{Mode: "tui"})
	if err != nil {
		t.Fatalf("NewAutoNamedWriter a: %v", err)
	}
	b, err := NewAutoNamedWriter(path, WriterConfig{}, FileMetadata{Mode: "tui"})
	if err != nil {
		t.Fatalf("NewWriter b: %v", err)
	}
	if a.TempPath() == b.TempPath() {
		t.Fatalf("both writers share temp file %q", a.TempPath())
	}
	if err := a.WriteRows(rowsA); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteRows(rowsB); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close a: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close b: %v", err)
	}

	if a.FinalPath() != path {
		t.Errorf("a.FinalPath() = %q, want %q", a.FinalPath(), path)
	}
	wantB := filepath.Join(dir, "trace-1.parquet")
	if b.FinalPath() != wantB {
		t.Errorf("b.FinalPath() = %q, want %q", b.FinalPath(), wantB)
	}
	if got := readAllRecords(t, a.FinalPath()); !reflect.DeepEqual(got, rowsA) {
		t.Errorf("a's file = %+v, want %+v", got, rowsA)
	}
	if got := readAllRecords(t, b.FinalPath()); !reflect.DeepEqual(got, rowsB) {
		t.Errorf("b's file = %+v, want %+v", got, rowsB)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("dir holds %v, want exactly the two recordings", entries)
	}
}

// TestExplicitPathWriterReplacesExistingFile pins the least-surprise policy
// for a user-chosen path (-parquet out.parquet): a second recording replaces
// the first at exactly that path, as it did before no-clobber publishing was
// introduced for generated names, and FinalPath stays the requested path.
func TestExplicitPathWriterReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chosen.parquet")
	first := []Record{{Seq: 1, Comm: "a", Syscall: "read"}}
	second := []Record{{Seq: 2, Comm: "b", Syscall: "write"}}

	for _, rows := range [][]Record{first, second} {
		w, err := NewWriter(path, WriterConfig{}, FileMetadata{Mode: "headless"})
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}
		if err := w.WriteRows(rows); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if w.FinalPath() != path {
			t.Errorf("FinalPath() = %q, want the requested %q", w.FinalPath(), path)
		}
	}
	if got := readAllRecords(t, path); !reflect.DeepEqual(got, second) {
		t.Errorf("file = %+v, want the second recording %+v", got, second)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %v, want only chosen.parquet", entries)
	}
}

func TestNewWriterMissingDirectoryFails(t *testing.T) {
	_, err := NewWriter(filepath.Join(t.TempDir(), "missing", "trace"), WriterConfig{}, FileMetadata{})
	if err == nil {
		t.Fatal("NewWriter in a missing directory succeeded, want error")
	}
}

func TestNormalizeOutputPath(t *testing.T) {
	for in, want := range map[string]string{
		"trace":             "trace.parquet",
		"trace.parquet":     "trace.parquet",
		"trace.parquet.tmp": "trace.parquet",
		"  dir/x.PARQUET  ": "dir/x.PARQUET",
	} {
		got, err := normalizeOutputPath(in)
		if err != nil || got != want {
			t.Errorf("normalizeOutputPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", "."} {
		if _, err := normalizeOutputPath(in); err == nil {
			t.Errorf("normalizeOutputPath(%q) succeeded, want error", in)
		}
	}
}
