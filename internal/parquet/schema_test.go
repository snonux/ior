package parquet

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"ior/internal/event"
	"ior/internal/streamrow"
	"ior/internal/textsafe"
	"ior/internal/types"
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
