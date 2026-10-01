package textsafe

import (
	"strings"
	"unicode/utf8"

	"ior/internal/types"
)

// This file holds the UTF-8 repair that every data file ior writes applies to
// its free-form traced text (comm, file, old_file): the Parquet recording
// (parquet.RecordFromStream), the stream CSV export (internal/tui/eventstream)
// and the dashboard snapshot CSV (internal/export). It lives here, not in
// internal/parquet, so the CSV writers share one definition of the repair
// without importing the Parquet library (task 4z2); the only extra dependency
// is internal/types for the BPF capture limit, which has no ior imports.
//
// Strict readers (DuckDB, Arrow, a strict csv reader) reject a whole query
// that touches a value holding an invalid UTF-8 byte. The traced values are
// not guaranteed valid: the kernel cuts comm at 15 bytes regardless of rune
// boundaries, the BPF side cuts a path at MAX_FILENAME_LENGTH-1 bytes just the
// same, and any local user can create file names (or, via
// prctl(PR_SET_NAME), comm names) with arbitrary bytes.

// maxCapturedPath is the longest path the BPF side captures: the
// MAX_FILENAME_LENGTH buffer minus its NUL terminator.
const maxCapturedPath = types.MAX_FILENAME_LENGTH - 1

// SanitizeUTF8 returns s unchanged when it is valid UTF-8 (the common case,
// checked without allocating). Otherwise every invalid byte is rewritten as
// the four characters \xHH (lower-case hex) by Escape, the single definition
// of that notation (also used by -plain and ior collapsed), so the operator
// can still see which byte was there. Valid runes, including valid control
// characters, are kept as they are: unlike Escape, this is a data-file repair,
// not terminal safety, and is independent of -escape.
//
// The mapping is deliberately not injective: a name that already contains the
// characters `\xff` is stored identically to one containing the byte 0xff, and
// a literal backslash is not doubled. Doubling every backslash would corrupt
// ordinary Windows-style names for the sake of a vanishingly rare collision,
// and an exact-bytes column would roughly double the size of the file.
//
// It does not trim a rune cut at a capture limit; use SanitizeComm or
// SanitizePath for traced comm and path values.
func SanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 12)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Only this rare path allocates; Escape of one invalid byte is
			// always exactly its \xHH form.
			b.WriteString(Escape(s[i : i+1]))
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// SanitizeComm makes a comm value valid UTF-8. The kernel cuts comm at 15
// bytes regardless of rune boundaries, so a partial trailing rune is dropped
// first (it is the cut-off half of a character, not corrupt data) and any
// other invalid byte, e.g. one set with prctl(PR_SET_NAME), is escaped.
//
// Unlike SanitizePath, the trim is applied at any length, not only at the
// 15-byte limit: a shorter comm ending in a lone lead byte (only possible via
// prctl) loses that byte instead of showing it as \xHH. That is accepted, as
// the byte carries no readable character either way.
func SanitizeComm(comm string) string {
	return SanitizeUTF8(TrimPartialRune(comm))
}

// SanitizePath makes a file/old_file value valid UTF-8. A path the BPF side
// captured in a full MAX_FILENAME_LENGTH buffer (bpf_probe_read_user_str
// stores at most MAX_FILENAME_LENGTH-1 bytes plus the NUL) was cut by bytes
// too, so a non-ASCII path can end in half a character; that partial rune is
// dropped like comm's. A getcwd path longer than the buffer is reported as
// the captured prefix plus "..." (types.TruncatedPathSuffix), so the cut rune
// sits in front of that suffix and is trimmed there.
//
// A name that went through dirfd resolution (openat, newfstatat, unlinkat,
// renameat2, execveat, ...) was already trimmed by the event loop before it
// was joined to the directory (eventloop_exit.go trimCutPathname), because
// the joined string no longer has the recognisable capture length; this
// function repairs what reaches it untrimmed (absolute/AT_FDCWD names never
// change length, and the getcwd form is built after the capture).
//
// Limitations: a path shorter than the limit is never trimmed, so an invalid
// trailing byte in it (a real file name ending in a lone lead byte) becomes a
// \xHH escape, as does every invalid byte elsewhere; and a real 255-byte path
// that happens to end in a lone lead byte is trimmed although it was not cut.
func SanitizePath(path string) string {
	switch {
	case len(path) == maxCapturedPath:
		path = TrimPartialRune(path)
	case len(path) == maxCapturedPath+len(types.TruncatedPathSuffix) && strings.HasSuffix(path, types.TruncatedPathSuffix):
		path = TrimPartialRune(path[:maxCapturedPath]) + types.TruncatedPathSuffix
	}
	return SanitizeUTF8(path)
}
