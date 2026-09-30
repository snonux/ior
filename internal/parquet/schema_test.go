package parquet

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"ior/internal/streamrow"
	"ior/internal/textsafe"
	"ior/internal/types"
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

func TestSanitizePath(t *testing.T) {
	// Exactly the BPF capture limit, cut inside "ä": the partial rune is
	// the kernel-side cut and is dropped, like comm's.
	full := capturedPath(types.MAX_FILENAME_LENGTH-2, "") + "\xc3"
	if len(full) != types.MAX_FILENAME_LENGTH-1 {
		t.Fatalf("test path length = %d, want %d", len(full), types.MAX_FILENAME_LENGTH-1)
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"valid", "/tmp/ü", "/tmp/ü"},
		{"limit-length path cut mid-rune", full, full[:len(full)-1]},
		{"limit-length path ending in a complete rune", capturedPath(types.MAX_FILENAME_LENGTH-1, "ä"), capturedPath(types.MAX_FILENAME_LENGTH-1, "ä")},
		{"limit-length path with mid-string invalid byte keeps the escape", "\xff" + full[1:len(full)-1] + "\xe6", `\xff` + full[1:len(full)-1]},
		// Shorter than the limit nothing was cut, so an invalid byte is corrupt
		// data (a real name), and is escaped rather than trimmed.
		{"short path ending in a lone lead byte is escaped", "/tmp/x\xe6", `/tmp/x\xe6`},
		{"short path mid-string invalid byte", "f\xff\xfeinv", `f\xff\xfeinv`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizePath(tt.in)
			if got != tt.want {
				t.Fatalf("sanitizePath(len %d) = %q, want %q", len(tt.in), got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("sanitizePath(len %d) is not valid UTF-8", len(tt.in))
			}
		})
	}
}

// TestSanitizePathTrimsTruncatedGetcwdPath covers the getcwd form: a path
// longer than the captured field is reported as the captured prefix plus
// types.TruncatedPathSuffix, so the byte-wise cut sits in front of the suffix.
func TestSanitizePathTrimsTruncatedGetcwdPath(t *testing.T) {
	prefix := capturedPath(types.MAX_FILENAME_LENGTH-2, "") + "\xc3"
	in := prefix + types.TruncatedPathSuffix
	want := prefix[:len(prefix)-1] + types.TruncatedPathSuffix
	if got := sanitizePath(in); got != want {
		t.Fatalf("sanitizePath = %q, want %q", got, want)
	}
	// A "..." suffix on a path of any other length is ordinary text.
	if got := sanitizePath("/tmp/\xc3..."); got != `/tmp/\xc3...` {
		t.Fatalf("short path with dots = %q", got)
	}
}

// TestSanitizeUTF8UsesTextsafeNotation pins that the \xHH form is exactly
// what textsafe.Escape produces for every possible invalid byte, so the two
// notations cannot drift apart.
func TestSanitizeUTF8UsesTextsafeNotation(t *testing.T) {
	for b := 0x80; b <= 0xff; b++ {
		in := string([]byte{byte(b)})
		if utf8.ValidString(in) {
			continue
		}
		if got, want := sanitizeUTF8(in), textsafe.Escape(in); got != want {
			t.Fatalf("byte 0x%02x: sanitizeUTF8 = %q, textsafe.Escape = %q", b, got, want)
		}
	}
}
