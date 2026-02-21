package integrationtests

import (
	"bytes"
	"encoding/gob"
	"ior/internal/file"
	"ior/internal/flamegraph"
	"ior/internal/types"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/zstd"
)

// writeIorZst creates a minimal .ior.zst file from known data.
// It encodes a pathMap (the same nested-map structure used internally by iorData)
// so that LoadTestResult can decode it via the public flamegraph.LoadFromFile API.
func writeIorZst(t *testing.T, dir string, records []flamegraph.IterRecord) string {
	t.Helper()

	// Build the nested map matching iorData.paths layout:
	//   path → traceId → comm → pid → tid → flags → Counter
	type (
		flagsMap    = map[file.Flags]flamegraph.Counter
		tidMap      = map[uint32]flagsMap
		pidMap      = map[uint32]tidMap
		commMap     = map[string]pidMap
		traceIdMap  = map[types.TraceId]commMap
		pathMapType = map[string]traceIdMap
	)

	paths := make(pathMapType)
	for _, r := range records {
		if paths[r.Path] == nil {
			paths[r.Path] = make(traceIdMap)
		}
		if paths[r.Path][r.TraceID] == nil {
			paths[r.Path][r.TraceID] = make(commMap)
		}
		if paths[r.Path][r.TraceID][r.Comm] == nil {
			paths[r.Path][r.TraceID][r.Comm] = make(pidMap)
		}
		if paths[r.Path][r.TraceID][r.Comm][r.Pid] == nil {
			paths[r.Path][r.TraceID][r.Comm][r.Pid] = make(tidMap)
		}
		if paths[r.Path][r.TraceID][r.Comm][r.Pid][r.Tid] == nil {
			paths[r.Path][r.TraceID][r.Comm][r.Pid][r.Tid] = make(flagsMap)
		}
		paths[r.Path][r.TraceID][r.Comm][r.Pid][r.Tid][r.Flags] = r.Cnt
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(paths); err != nil {
		t.Fatalf("gob encode: %v", err)
	}

	filePath := filepath.Join(dir, "test.ior.zst")
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer f.Close()

	w := zstd.NewWriter(f)
	if _, err := w.Write(buf.Bytes()); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}

	return filePath
}

func TestLoadTestResultAllFields(t *testing.T) {
	input := []flamegraph.IterRecord{
		{
			Path:    "/tmp/testfile.txt",
			TraceID: types.SYS_ENTER_OPENAT,
			Comm:    "mycomm",
			Pid:     1234,
			Tid:     5678,
			Flags:   file.Flags(0), // O_RDONLY
			Cnt:     flamegraph.Counter{Count: 10, Duration: 500, DurationToPrev: 50, Bytes: 0},
		},
		{
			Path:    "/var/log/syslog",
			TraceID: types.SYS_ENTER_WRITE,
			Comm:    "writer",
			Pid:     4321,
			Tid:     8765,
			Flags:   file.Flags(1), // O_WRONLY
			Cnt:     flamegraph.Counter{Count: 3, Duration: 100, DurationToPrev: 10, Bytes: 256},
		},
	}

	dir := t.TempDir()
	iorFile := writeIorZst(t, dir, input)

	result, err := LoadTestResult(iorFile)
	if err != nil {
		t.Fatalf("LoadTestResult: %v", err)
	}

	if len(result.Records) != len(input) {
		t.Fatalf("got %d records, want %d", len(result.Records), len(input))
	}

	// Build a lookup by Path since map iteration order is not deterministic.
	byPath := make(map[string]flamegraph.IterRecord, len(result.Records))
	for _, rec := range result.Records {
		byPath[rec.Path] = rec
	}

	for _, want := range input {
		got, ok := byPath[want.Path]
		if !ok {
			t.Errorf("record with path %q not found", want.Path)
			continue
		}
		if got.TraceID != want.TraceID {
			t.Errorf("path %q: TraceID = %v, want %v", want.Path, got.TraceID, want.TraceID)
		}
		if got.Comm != want.Comm {
			t.Errorf("path %q: Comm = %q, want %q", want.Path, got.Comm, want.Comm)
		}
		if got.Pid != want.Pid {
			t.Errorf("path %q: Pid = %d, want %d", want.Path, got.Pid, want.Pid)
		}
		if got.Tid != want.Tid {
			t.Errorf("path %q: Tid = %d, want %d", want.Path, got.Tid, want.Tid)
		}
		if got.Flags != want.Flags {
			t.Errorf("path %q: Flags = %v, want %v", want.Path, got.Flags, want.Flags)
		}
		if got.Cnt != want.Cnt {
			t.Errorf("path %q: Cnt = %+v, want %+v", want.Path, got.Cnt, want.Cnt)
		}
	}
}

func TestLoadTestResultMultipleRecordsSamePath(t *testing.T) {
	input := []flamegraph.IterRecord{
		{
			Path:    "/tmp/shared.txt",
			TraceID: types.SYS_ENTER_READ,
			Comm:    "reader",
			Pid:     100,
			Tid:     200,
			Flags:   file.Flags(0),
			Cnt:     flamegraph.Counter{Count: 5, Duration: 300, Bytes: 128},
		},
		{
			Path:    "/tmp/shared.txt",
			TraceID: types.SYS_ENTER_WRITE,
			Comm:    "reader",
			Pid:     100,
			Tid:     200,
			Flags:   file.Flags(1),
			Cnt:     flamegraph.Counter{Count: 2, Duration: 100, Bytes: 64},
		},
	}

	dir := t.TempDir()
	iorFile := writeIorZst(t, dir, input)

	result, err := LoadTestResult(iorFile)
	if err != nil {
		t.Fatalf("LoadTestResult: %v", err)
	}

	if len(result.Records) != 2 {
		t.Fatalf("got %d records, want 2", len(result.Records))
	}

	// Build lookup by TraceID since both records share the same path.
	byTraceID := make(map[types.TraceId]flamegraph.IterRecord, len(result.Records))
	for _, rec := range result.Records {
		byTraceID[rec.TraceID] = rec
	}

	for _, want := range input {
		got, ok := byTraceID[want.TraceID]
		if !ok {
			t.Errorf("record with TraceID %v not found", want.TraceID)
			continue
		}
		if got.Path != want.Path {
			t.Errorf("TraceID %v: Path = %q, want %q", want.TraceID, got.Path, want.Path)
		}
		if got.Comm != want.Comm {
			t.Errorf("TraceID %v: Comm = %q, want %q", want.TraceID, got.Comm, want.Comm)
		}
		if got.Pid != want.Pid {
			t.Errorf("TraceID %v: Pid = %d, want %d", want.TraceID, got.Pid, want.Pid)
		}
		if got.Tid != want.Tid {
			t.Errorf("TraceID %v: Tid = %d, want %d", want.TraceID, got.Tid, want.Tid)
		}
		if got.Flags != want.Flags {
			t.Errorf("TraceID %v: Flags = %v, want %v", want.TraceID, got.Flags, want.Flags)
		}
		if got.Cnt != want.Cnt {
			t.Errorf("TraceID %v: Cnt = %+v, want %+v", want.TraceID, got.Cnt, want.Cnt)
		}
	}
}

func TestLoadTestResultEmpty(t *testing.T) {
	dir := t.TempDir()
	iorFile := writeIorZst(t, dir, nil)

	result, err := LoadTestResult(iorFile)
	if err != nil {
		t.Fatalf("LoadTestResult: %v", err)
	}

	if len(result.Records) != 0 {
		t.Errorf("got %d records, want 0", len(result.Records))
	}
}

func TestLoadTestResultFileNotFound(t *testing.T) {
	_, err := LoadTestResult("/nonexistent/path/test.ior.zst")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadTestResultInvalidData(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "garbage.ior.zst")

	// Write valid zstd containing garbage (not gob-encoded).
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	w := zstd.NewWriter(f)
	if _, err := w.Write([]byte("this is not gob data")); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	w.Close()
	f.Close()

	_, err = LoadTestResult(filePath)
	if err == nil {
		t.Fatal("expected error for invalid gob data, got nil")
	}
}

func TestLoadTestResultCorruptZstd(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "corrupt.ior.zst")

	// Write raw bytes that are not valid zstd.
	if err := os.WriteFile(filePath, []byte("not zstd at all"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := LoadTestResult(filePath)
	if err == nil {
		t.Fatal("expected error for corrupt zstd data, got nil")
	}
}
