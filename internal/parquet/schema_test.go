package parquet

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"ior/internal/event"
	"ior/internal/streamrow"
	"ior/internal/textsafe"
	"ior/internal/types"

	parquetgo "github.com/parquet-go/parquet-go"
)

// TestRecordFromStreamProducesValidUTF8 pins that RecordFromStream applies
// the comm repair (cut rune dropped, other invalid bytes escaped) to comm and
// the escape to file/old_file; the repair functions themselves are tested in
// internal/textsafe (utf8repair_test.go).
func TestRecordFromStreamProducesValidUTF8(t *testing.T) {
	// A comm can hold an invalid byte that is not a trailing cut (prctl
	// PR_SET_NAME accepts arbitrary bytes): it must be escaped, not dropped.
	if got := RecordFromStream(streamrow.Row{Comm: "a\xffb"}, 0).Comm; got != `a\xffb` {
		t.Errorf("Comm with a mid-string invalid byte = %q, want %q", got, `a\xffb`)
	}
	// A trailing cut and a mid-string invalid byte together.
	if got := RecordFromStream(streamrow.Row{Comm: "a\xffä\xc3"}, 0).Comm; got != `a\xffä` {
		t.Errorf("Comm with both = %q, want %q", got, `a\xffä`)
	}
	row := streamrow.Row{
		Seq:      1,
		Syscall:  "renameat2",
		Comm:     "äääääää\xc3", // kernel truncation mid-rune
		FileName: "/tmp/f\xff\xfeinv",
		OldName:  "/tmp/old\x80",
	}
	rec := RecordFromStream(row, 0)
	if rec.Comm != "äääääää" {
		t.Errorf("Comm = %q, want the partial trailing rune trimmed", rec.Comm)
	}
	if rec.File != `/tmp/f\xff\xfeinv` {
		t.Errorf("File = %q", rec.File)
	}
	if rec.OldFile != `/tmp/old\x80` {
		t.Errorf("OldFile = %q", rec.OldFile)
	}
}

// TestInvalidUTF8RoundTripsAsValidStrings writes rows carrying the values that
// made DuckDB reject every query touching comm/file/old_file ("Invalid string
// encoding found in Parquet file") and requires every string column read back
// from the finished file to be valid UTF-8. The control half shows the test
// can fail: a Record built by hand, bypassing RecordFromStream, keeps its
// invalid bytes in the file.
func TestInvalidUTF8RoundTripsAsValidStrings(t *testing.T) {
	var rows []Record
	for _, r := range []streamrow.Row{
		{Seq: 1, Syscall: "openat", Comm: "äääääää\xc3", FileName: "f\xff\xfeinv"},
		{Seq: 2, Syscall: "rename", Comm: "ok", FileName: "/new", OldName: "/old\xc3"},
		{Seq: 3, Syscall: "read", Comm: "日本語", FileName: "/tmp/ü"},
		{Seq: 4, Syscall: "read", Comm: "a\xffb", FileName: "/x"},
	} {
		rows = append(rows, RecordFromStream(r, 0))
	}
	got := writeAndReadBack(t, rows)
	if len(got) != len(rows) {
		t.Fatalf("read %d rows, want %d", len(got), len(rows))
	}
	for i, rec := range got {
		for name, v := range map[string]string{"comm": rec.Comm, "file": rec.File, "old_file": rec.OldFile} {
			if !utf8.ValidString(v) {
				t.Errorf("row %d column %s = %q is not valid UTF-8", i, name, v)
			}
		}
	}
	if got[0].Comm != "äääääää" || got[0].File != `f\xff\xfeinv` || got[1].OldFile != `/old\xc3` {
		t.Errorf("unexpected sanitized values: %+v", got)
	}
	if got[2].Comm != "日本語" || got[2].File != "/tmp/ü" {
		t.Errorf("valid text changed: %+v", got[2])
	}

	if got[3].Comm != `a\xffb` {
		t.Errorf("mid-string invalid comm byte = %q, want it escaped", got[3].Comm)
	}

	raw := writeAndReadBack(t, []Record{{Seq: 1, Comm: "x\xc3"}})
	if utf8.ValidString(raw[0].Comm) {
		t.Fatalf("control: a hand-built Record was expected to keep its invalid bytes, got %q", raw[0].Comm)
	}
}

func writeAndReadBack(t *testing.T, rows []Record) []Record {
	t.Helper()
	writer, err := NewWriter(filepath.Join(t.TempDir(), "trace"), WriterConfig{}, FileMetadata{Mode: "test"})
	if err != nil {
		t.Fatalf("NewWriter() error = %v", err)
	}
	if err := writer.WriteRows(rows); err != nil {
		t.Fatalf("WriteRows() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return readAllRecords(t, writer.FinalPath())
}

// capturedPath builds a path of exactly n bytes: "/" plus filler of the
// two-byte rune ä, padded with an ASCII byte when n is even so the total is n.
func capturedPath(n int, tail string) string {
	base := "/" + strings.Repeat("ä", (n-1-len(tail))/2)
	for len(base)+len(tail) < n {
		base += "x"
	}
	return base + tail
}

// TestRecordFromStreamTrimsCutPaths pins that RecordFromStream applies the
// path repair (textsafe.SanitizePath) to both file and old_file, in the plain
// limit form and the getcwd "..." form: replacing either call with the plain
// textsafe.SanitizeUTF8 would leave a "\xc3" residue and fail here. The repair
// itself is tested in internal/textsafe (utf8repair_test.go).
func TestRecordFromStreamTrimsCutPaths(t *testing.T) {
	cut := capturedPath(types.MAX_FILENAME_LENGTH-2, "") + "\xc3"
	trimmed := cut[:len(cut)-1]
	getcwdCut := cut + types.TruncatedPathSuffix
	getcwdTrimmed := trimmed + types.TruncatedPathSuffix
	if len(getcwdCut) != types.MAX_FILENAME_LENGTH+2 {
		t.Fatalf("getcwd form length = %d, want %d", len(getcwdCut), types.MAX_FILENAME_LENGTH+2)
	}
	tests := []struct {
		name              string
		fileName, oldNam  string
		wantFile, wantOld string
	}{
		{"file only", cut, "", trimmed, ""},
		{"old_file only", "", cut, "", trimmed},
		{"both", cut, cut, trimmed, trimmed},
		{"getcwd file", getcwdCut, "", getcwdTrimmed, ""},
		{"getcwd old_file", "", getcwdCut, "", getcwdTrimmed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := RecordFromStream(streamrow.Row{FileName: tt.fileName, OldName: tt.oldNam}, 0)
			if rec.File != tt.wantFile {
				t.Errorf("File tail = %q, want tail %q", tail(rec.File), tail(tt.wantFile))
			}
			if rec.OldFile != tt.wantOld {
				t.Errorf("OldFile tail = %q, want tail %q", tail(rec.OldFile), tail(tt.wantOld))
			}
		})
	}
}

// TestRecordFromStreamUsesTextsafeRepair pins that the recording's text
// columns are exactly what the shared textsafe repair produces, so the stream
// and snapshot CSV exports, which call textsafe directly, hold the same text
// as the recording (task 4z2). A Parquet-local variant of the repair would
// diverge on one of these inputs.
func TestRecordFromStreamUsesTextsafeRepair(t *testing.T) {
	cut := capturedPath(types.MAX_FILENAME_LENGTH-2, "") + "\xc3"
	for _, in := range []string{
		"", "ok", "日本語", "äääääää\xc3", "a\xffb", "ab\xff", "/tmp/x\xe6",
		cut, cut + types.TruncatedPathSuffix, "f\xff\xfeinv",
	} {
		rec := RecordFromStream(streamrow.Row{Comm: in, FileName: in, OldName: in}, 0)
		if want := textsafe.SanitizeComm(in); rec.Comm != want {
			t.Errorf("Comm(%q) = %q, want textsafe.SanitizeComm %q", tail(in), tail(rec.Comm), tail(want))
		}
		want := textsafe.SanitizePath(in)
		if rec.File != want || rec.OldFile != want {
			t.Errorf("File/OldFile(%q) = %q/%q, want textsafe.SanitizePath %q", tail(in), tail(rec.File), tail(rec.OldFile), tail(want))
		}
	}
}

// tail returns the last few bytes of s for compact failure messages.
func tail(s string) string {
	if len(s) > 8 {
		return s[len(s)-8:]
	}
	return s
}

// TestFilelessRowPersistsEmptyFileAndNegativeFD is the task pq2 regression: the
// "N:file" placeholder is display text, so a row without a file must reach the
// Parquet file with an empty `file` (docs/parquet-querying.md: "file != empty"
// selects rows that have a file) and the UnknownFD (-1) descriptor, while a
// row whose file is really named "N:file" keeps that name (task zp2's
// distinction, carried into the data file). Checked through a written file, not
// just RecordFromStream, so the column the query engines see is what is pinned.
func TestFilelessRowPersistsEmptyFileAndNegativeFD(t *testing.T) {
	fileless := streamrow.Row{Seq: 1, Syscall: "sync", FileName: event.NoFileName, NoFile: true, FD: streamrow.UnknownFD}
	realNamed := streamrow.Row{Seq: 2, Syscall: "openat", FileName: event.NoFileName, FD: 3}
	normal := streamrow.Row{Seq: 3, Syscall: "read", FileName: "/tmp/f", FD: 3}

	var rows []Record
	for _, r := range []streamrow.Row{fileless, realNamed, normal} {
		rows = append(rows, RecordFromStream(r, 0))
	}
	got := writeAndReadBack(t, rows)
	if len(got) != 3 {
		t.Fatalf("read %d rows, want 3", len(got))
	}
	if got[0].File != "" || got[0].FD != -1 {
		t.Errorf("fileless row persisted file=%q fd=%d, want empty file and fd -1", got[0].File, got[0].FD)
	}
	if got[1].File != event.NoFileName {
		t.Errorf("real file named %q persisted as %q, want its real name", event.NoFileName, got[1].File)
	}
	if got[2].File != "/tmp/f" {
		t.Errorf("ordinary row file = %q, want /tmp/f", got[2].File)
	}
	// A fileless row must not be counted as having a file: the documented
	// `WHERE file != ''` predicate.
	withFile := 0
	for _, rec := range got {
		if rec.File != "" {
			withFile++
		}
	}
	if withFile != 2 {
		t.Errorf("rows with a file = %d, want 2 (placeholder row counted as a file?)", withFile)
	}
}

// TestRestartsColumnRoundTrips covers task 203: the count of kernel restarts
// folded into a row is written as the `restarts` column and read back exactly,
// from 0 (an uninterrupted call, or one that kept its restart code) to the
// saturated 255. Checked through a written file, so the column the query
// engines see is what is pinned.
func TestRestartsColumnRoundTrips(t *testing.T) {
	counts := []uint8{0, 1, 2, 255, 0}
	var rows []Record
	for i, n := range counts {
		row := streamrow.Row{Seq: uint64(i + 1), Syscall: "clock_nanosleep", Restarts: n}
		if i == len(counts)-1 {
			row.RetVal = -516 // not folded: the restart code stays, the count is 0
		}
		rows = append(rows, RecordFromStream(row, 0))
	}
	got := writeAndReadBack(t, rows)
	if len(got) != len(counts) {
		t.Fatalf("read %d rows, want %d", len(got), len(counts))
	}
	for i, n := range counts {
		if got[i].Restarts != n {
			t.Errorf("row %d restarts = %d, want %d", i+1, got[i].Restarts, n)
		}
	}
	if got[4].Ret != -516 {
		t.Errorf("unfolded row ret = %d, want -516", got[4].Ret)
	}
}

// TestRestartsIsTheLastUInt8Column pins how the column reaches a reader:
// under the name `restarts`, as an unsigned 8-bit integer (ClickHouse UInt8,
// DuckDB UTINYINT), required like every other column, and appended after the
// columns that existed before it, whose order must not change.
func TestRestartsIsTheLastUInt8Column(t *testing.T) {
	schema := parquetgo.SchemaOf(Record{})
	fields := schema.Fields()
	wantOrder := []string{
		"seq", "time_ns", "gap_ns", "latency_ns", "comm", "pid", "tid", "syscall",
		"family", "fd", "ret", "bytes", "address_space_bytes", "requested_sleep_ns",
		"nfds", "timeout_ns", "file", "is_error", "filter_epoch", "old_file",
		"epoll_op", "epoll_target_fd", "epoll_events", "restarts",
	}
	var names []string
	for _, f := range fields {
		names = append(names, f.Name())
	}
	if !slices.Equal(names, wantOrder) {
		t.Fatalf("columns = %v, want %v", names, wantOrder)
	}
	last := fields[len(fields)-1]
	if last.Optional() || last.Repeated() {
		t.Errorf("restarts is optional/repeated, want a required column like the others")
	}
	if got, want := last.Type().String(), parquetgo.Uint(8).Type().String(); got != want {
		t.Errorf("restarts type = %s, want %s", got, want)
	}
}

// recordBeforeRestarts is the schema as recordings made before task 203 have
// it: parquet.Record without its last column.
type recordBeforeRestarts struct {
	Seq               uint64 `parquet:"seq"`
	TimeNS            uint64 `parquet:"time_ns"`
	GapNS             uint64 `parquet:"gap_ns"`
	LatencyNS         uint64 `parquet:"latency_ns"`
	Comm              string `parquet:"comm"`
	PID               uint32 `parquet:"pid"`
	TID               uint32 `parquet:"tid"`
	Syscall           string `parquet:"syscall"`
	Family            string `parquet:"family"`
	FD                int32  `parquet:"fd"`
	Ret               int64  `parquet:"ret"`
	Bytes             uint64 `parquet:"bytes"`
	AddressSpaceBytes uint64 `parquet:"address_space_bytes"`
	RequestedSleepNS  int64  `parquet:"requested_sleep_ns"`
	Nfds              int32  `parquet:"nfds"`
	TimeoutNS         int64  `parquet:"timeout_ns"`
	File              string `parquet:"file"`
	IsError           bool   `parquet:"is_error"`
	FilterEpoch       uint64 `parquet:"filter_epoch"`
	OldFile           string `parquet:"old_file"`
	EpollOp           string `parquet:"epoll_op"`
	EpollTargetFD     int32  `parquet:"epoll_target_fd"`
	EpollEvents       uint32 `parquet:"epoll_events"`
}

// TestRecordingsAcrossTheRestartsColumnStayReadable is the compatibility
// check of the appended column, both ways. A recording made before it has no
// `restarts` column: read with today's Record its rows come back whole, with
// restarts 0. A recording made now, read by a reader that only knows the
// earlier columns, gives those columns unchanged and ignores the new one.
func TestRecordingsAcrossTheRestartsColumnStayReadable(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.parquet")
	old := []recordBeforeRestarts{{Seq: 1, Syscall: "read", Ret: 9, File: "/f", EpollEvents: 5}}
	if err := parquetgo.WriteFile(oldPath, old); err != nil {
		t.Fatalf("write a recording without the column: %v", err)
	}
	got := readAllRecords(t, oldPath)
	want := Record{Seq: 1, Syscall: "read", Ret: 9, File: "/f", EpollEvents: 5}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("old recording read as %+v, want %+v", got, want)
	}

	newPath := filepath.Join(dir, "new.parquet")
	if err := parquetgo.WriteFile(newPath, []Record{{Seq: 2, Syscall: "poll", Ret: 1, EpollEvents: 6, Restarts: 3}}); err != nil {
		t.Fatalf("write a recording with the column: %v", err)
	}
	legacy, err := parquetgo.ReadFile[recordBeforeRestarts](newPath)
	if err != nil {
		t.Fatalf("read a recording with the column through the old schema: %v", err)
	}
	wantLegacy := recordBeforeRestarts{Seq: 2, Syscall: "poll", Ret: 1, EpollEvents: 6}
	if len(legacy) != 1 || legacy[0] != wantLegacy {
		t.Fatalf("new recording read through the old schema as %+v, want %+v", legacy, wantLegacy)
	}
}
