package parquet

import (
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
	defer f.Close()

	reader := parquetgo.NewGenericReader[Record](f)
	defer reader.Close()

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
		if err == io.EOF {
			return rows
		}
		t.Fatalf("Read() error = %v", err)
	}
}
