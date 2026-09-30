package parquet

import (
	"path/filepath"
	"testing"
	"unicode/utf8"

	"ior/internal/streamrow"
)

func TestSanitizeUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"ascii", "/tmp/file", "/tmp/file"},
		{"valid multibyte kept", "/tmp/äö/日本語/😀", "/tmp/äö/日本語/😀"},
		{"valid controls kept", "a\tb\nc\x00", "a\tb\nc\x00"},
		{"lone high byte", "f\xff\xfeinv", `f\xff\xfeinv`},
		{"truncated rune", "abc\xc3", `abc\xc3`},
		{"stray continuation", "\x80x", `\x80x`},
		{"overlong encoding", "\xc0\xaf", `\xc0\xaf`},
		{"utf-16 surrogate", "\xed\xa0\x80", `\xed\xa0\x80`},
		{"valid runes around invalid byte", "ä\xffö", `ä\xffö`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeUTF8(tt.in)
			if got != tt.want {
				t.Fatalf("sanitizeUTF8(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("sanitizeUTF8(%q) = %q is not valid UTF-8", tt.in, got)
			}
		})
	}
}

// TestSanitizeUTF8DoesNotAllocateForValidText pins the fast path: almost
// every traced string is valid, so the hot recording path must not pay for
// the rare invalid one.
func TestSanitizeUTF8DoesNotAllocateForValidText(t *testing.T) {
	const s = "/var/log/ünïcode/access.log"
	if allocs := testing.AllocsPerRun(100, func() { _ = sanitizeUTF8(s) }); allocs != 0 {
		t.Fatalf("sanitizeUTF8 allocated %v times for valid text, want 0", allocs)
	}
}

func TestTrimPartialRune(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"ascii", "kworker/0:1", "kworker/0:1"},
		{"complete two-byte rune", "ä", "ä"},
		{"kernel cut of 10 umlauts", "äääääää\xc3", "äääääää"},
		{"three-byte rune cut after one byte", "ab\xe6", "ab"},
		{"three-byte rune cut after two bytes", "ab\xe6\x97", "ab"},
		{"four-byte rune cut after three bytes", "a\xf0\x9f\x98", "a"},
		{"complete four-byte rune", "a😀", "a😀"},
		{"only a partial rune", "\xc3", ""},
		// Not the start of a longer valid sequence: left for sanitizeUTF8.
		{"trailing invalid byte", "ab\xff", "ab\xff"},
		{"stray continuation byte", "ab\x80", "ab\x80"},
		{"invalid sequence already full", "a\xe6\x28", "a\xe6\x28"},
		{"invalid byte before valid tail", "\xffab", "\xffab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimPartialRune(tt.in); got != tt.want {
				t.Fatalf("trimPartialRune(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRecordFromStreamProducesValidUTF8(t *testing.T) {
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
