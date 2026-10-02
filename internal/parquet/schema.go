package parquet

import (
	"os"
	"strconv"
	"time"

	"ior/internal/flags"
	"ior/internal/sampling"
	"ior/internal/streamrow"
	"ior/internal/textsafe"

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
// with arbitrary bytes. RecordFromStream therefore repairs them with
// textsafe.SanitizeComm/SanitizePath (internal/textsafe/utf8repair.go, shared
// with the stream and snapshot CSV exports); a Record built by hand is written
// as given.
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
	// Restarts is the number of kernel restarts folded into the row (task 203;
	// streamrow.Row.Restarts): each restart_syscall continuation of a call
	// stopped with -516 and each re-execution after -512/-513/-514 counts one,
	// saturating at 255. Such a row holds the call's final return, so this
	// column is what tells it from an uninterrupted call. 0 for every other
	// row; a row folded N times and then interrupted once more with that hop
	// refused has both a count and a restart code in ret. It is the last
	// column on purpose: columns are only appended, and a
	// recording made before it simply has no such column (readers that select
	// by name see it as missing, parquet-go fills in 0).
	Restarts uint8 `parquet:"restarts"`
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
// Free-form traced text (comm, file, old_file) is made valid UTF-8 first
// (textsafe.SanitizeComm/SanitizePath) so the STRING columns stay readable by
// strict Parquet readers. The rewrite happens here, on the single
// row-to-Record path, so every recording (TUI, plain, headless) gets it; the
// stream CSV export applies the same textsafe functions to the same fields, so
// both files hold identical text for a row.
func RecordFromStream(row streamrow.Row, filterEpoch uint64) Record {
	return Record{
		Seq:               row.Seq,
		TimeNS:            row.TimeNs,
		GapNS:             row.GapNs,
		LatencyNS:         row.DurationNs,
		Comm:              textsafe.SanitizeComm(row.Comm),
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
		File:          textsafe.SanitizePath(row.FileValue()),
		IsError:       row.IsError,
		FilterEpoch:   filterEpoch,
		OldFile:       textsafe.SanitizePath(row.OldName),
		EpollOp:       row.EpollOp,
		EpollTargetFD: row.EpollTargetFD,
		EpollEvents:   row.EpollEvents,
		Restarts:      row.Restarts,
	}
}

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
