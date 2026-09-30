package parquet

import (
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"ior/internal/flags"
	"ior/internal/sampling"
	"ior/internal/streamrow"
	"ior/internal/textsafe"
	"ior/internal/types"

	parquetgo "github.com/parquet-go/parquet-go"
)

// Record is the persisted Parquet schema for one syscall stream row.
//
// The string columns (comm, file, old_file, ...) are annotated STRING/UTF8, and
// strict readers (DuckDB, Arrow) reject a whole query that touches a column
// holding an invalid UTF-8 byte. The traced values are not guaranteed valid:
// the kernel cuts comm at 15 bytes regardless of rune boundaries, the BPF
// side cuts a path at MAX_FILENAME_LENGTH-1 bytes just the same, and any
// local user can create file names (or, via prctl(PR_SET_NAME), comm names)
// with arbitrary bytes. RecordFromStream therefore sanitizes them (see
// sanitizeUTF8, textsafe.TrimPartialRune and sanitizeComm/sanitizePath); a Record
// built by hand is written as given.
//
// No-file and no-descriptor conventions (task pq2): File is empty when the
// syscall has no file. The "N:file" placeholder of the terminal views is
// display text and is never persisted, so a non-empty `file` selects exactly the
// rows with a file and a real file literally named "N:file" keeps that name. FD is
// -1 (streamrow.UnknownFD) when the syscall has no descriptor, not 0: 0 is a
// real descriptor (stdin), so a zero would make "none" indistinguishable from it.
type Record struct {
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
	// OldFile is the source/old path for rename-family (rename/renameat/
	// renameat2) and link-family (link/linkat/symlink/symlinkat) syscalls; the
	// `file` column carries the "new" path. This is the only place the captured
	// oldname (BPF name_event.oldname, at args[1] for the AT-variants) is
	// persisted. Empty for every other syscall.
	OldFile string `parquet:"old_file"`
	// EpollOp/EpollTargetFD/EpollEvents surface epoll_ctl control metadata: the
	// operation (ADD/MOD/DEL), the target descriptor registered (args[2]), and
	// the requested event mask (args[3]->events). EpollOp is empty and the
	// numeric fields are zero for all non-epoll_ctl rows.
	EpollOp       string `parquet:"epoll_op"`
	EpollTargetFD int32  `parquet:"epoll_target_fd"`
	EpollEvents   uint32 `parquet:"epoll_events"`
}

// Footer key/value keys that mark a recording as sampled (see
// sampling.Summary). Both are absent from a recording that traced every syscall
// in full, so `ior.sampling` being present is the marker.
const (
	// KeySampling holds the effective rates, "read=10,write=0" (0 is
	// aggregate-only: no rows at all). Written when the file is created.
	KeySampling = "ior.sampling"
	// KeySamplingTotals holds the exact per-syscall population as a JSON array
	// (rows written plus invocations only the kernel counted), or the word
	// "unavailable". Written when the recording stops, since the counts are
	// only known then (Recorder.SetSamplingTotals).
	KeySamplingTotals = "ior.sampling.totals"
)

// FileMetadata captures constant metadata written once into the parquet file.
type FileMetadata struct {
	Hostname          string
	StartedAtUnixNano uint64
	Mode              string
	IORVersion        string
	// Sampling carries the run's effective sampling rates; only its entries'
	// Syscall and Rate are written here (KeySampling). The zero value, a run
	// that sampled nothing, writes no sampling key.
	Sampling sampling.Summary
}

// NewFileMetadata constructs file-level metadata for a parquet trace file,
// populating the hostname, timestamp, version, and recording mode.
func NewFileMetadata(mode string) FileMetadata {
	meta := FileMetadata{
		StartedAtUnixNano: uint64(time.Now().UnixNano()),
		Mode:              mode,
		IORVersion:        flags.Version,
	}
	if hostname, err := os.Hostname(); err == nil {
		meta.Hostname = hostname
	}
	return meta
}

// RecordFromStream converts one shared stream row into the persisted format.
// Free-form traced text (comm, file, old_file) is made valid UTF-8 first so
// the STRING columns stay readable by strict Parquet readers. The rewrite
// happens here, on the single row-to-Record path, so every recording (TUI,
// plain, headless) gets it.
func RecordFromStream(row streamrow.Row, filterEpoch uint64) Record {
	return Record{
		Seq:               row.Seq,
		TimeNS:            row.TimeNs,
		GapNS:             row.GapNs,
		LatencyNS:         row.DurationNs,
		Comm:              sanitizeComm(row.Comm),
		PID:               row.PID,
		TID:               row.TID,
		Syscall:           row.Syscall,
		Family:            row.Family,
		FD:                row.FD,
		Ret:               row.RetVal,
		Bytes:             row.Bytes,
		AddressSpaceBytes: row.AddressSpaceBytes,
		RequestedSleepNS:  row.RequestedSleepNs,
		Nfds:              row.Nfds,
		TimeoutNS:         row.TimeoutNs,
		// FileValue, not FileName: a fileless row's FileName is the "N:file"
		// display placeholder, which must not be persisted (task pq2).
		File:          sanitizePath(row.FileValue()),
		IsError:       row.IsError,
		FilterEpoch:   filterEpoch,
		OldFile:       sanitizePath(row.OldName),
		EpollOp:       row.EpollOp,
		EpollTargetFD: row.EpollTargetFD,
		EpollEvents:   row.EpollEvents,
	}
}

// sanitizeUTF8 returns s unchanged when it is valid UTF-8 (the common case,
// checked without allocating). Otherwise every invalid byte is rewritten as
// the four characters \xHH (lower-case hex) by textsafe.Escape, the single
// definition of that notation (also used by -plain and ior collapsed), so the
// operator can still see which byte was there.
// Valid runes, including valid control characters, are kept as they are.
//
// The mapping is deliberately not injective: a name that already contains the
// characters `\xff` is stored identically to one containing the byte 0xff, and
// a literal backslash is not doubled. Doubling every backslash would corrupt
// ordinary Windows-style names for the sake of a vanishingly rare collision,
// and an exact-bytes column would roughly double the size of the file.
func sanitizeUTF8(s string) string {
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
			b.WriteString(textsafe.Escape(s[i : i+1]))
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// sanitizeComm makes a comm value valid UTF-8. The kernel cuts comm at 15
// bytes regardless of rune boundaries, so a partial trailing rune is dropped
// first (it is the cut-off half of a character, not corrupt data) and any
// other invalid byte, e.g. one set with prctl(PR_SET_NAME), is escaped.
func sanitizeComm(comm string) string {
	return sanitizeUTF8(textsafe.TrimPartialRune(comm))
}

// sanitizePath makes a file/old_file value valid UTF-8. A path the BPF side
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
func sanitizePath(path string) string {
	switch {
	case len(path) == maxCapturedPath:
		path = textsafe.TrimPartialRune(path)
	case len(path) == maxCapturedPath+len(types.TruncatedPathSuffix) && strings.HasSuffix(path, types.TruncatedPathSuffix):
		path = textsafe.TrimPartialRune(path[:maxCapturedPath]) + types.TruncatedPathSuffix
	}
	return sanitizeUTF8(path)
}

// maxCapturedPath is the longest path the BPF side captures: the
// MAX_FILENAME_LENGTH buffer minus its NUL terminator.
const maxCapturedPath = types.MAX_FILENAME_LENGTH - 1

func writerMetadataOptions(meta FileMetadata) []parquetgo.WriterOption {
	meta = normalizeMetadata(meta)
	options := make([]parquetgo.WriterOption, 0, 4)
	if meta.Hostname != "" {
		options = append(options, parquetgo.KeyValueMetadata("ior.hostname", meta.Hostname))
	}
	if meta.StartedAtUnixNano != 0 {
		options = append(options, parquetgo.KeyValueMetadata("ior.started_at_unix_nano", strconv.FormatUint(meta.StartedAtUnixNano, 10)))
	}
	if meta.Mode != "" {
		options = append(options, parquetgo.KeyValueMetadata("ior.mode", meta.Mode))
	}
	if meta.IORVersion != "" {
		options = append(options, parquetgo.KeyValueMetadata("ior.version", meta.IORVersion))
	}
	if rates := meta.Sampling.Rates(); rates != "" {
		options = append(options, parquetgo.KeyValueMetadata(KeySampling, rates))
	}
	return options
}

func normalizeMetadata(meta FileMetadata) FileMetadata {
	if meta.IORVersion == "" {
		meta.IORVersion = flags.Version
	}
	return meta
}
