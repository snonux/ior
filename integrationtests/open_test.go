package integrationtests

import (
	"strings"
	"syscall"
	"testing"

	iorparquet "ior/internal/parquet"
)

func TestOpenBasic(t *testing.T) {
	runScenario(t, "open-basic", []ExpectedEvent{
		{
			PathContains: "testfile.txt",
			Tracepoint:   "enter_openat",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CREAT,
			},
		},
	})
}

func TestOpenDirfdPaths(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "open-dirfd-paths", defaultDuration, nil, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains: "dirfd-base/relative-openat.txt",
			Syscall:      "openat",
			Comm:         "ioworkload",
			FDAtLeast:    ptrTo(int32(1)),
		},
		{
			FileContains: "dirfd-base",
			Syscall:      "statx",
			Comm:         "ioworkload",
			FDAtLeast:    ptrTo(int32(1)),
		},
		{
			FileContains: "dirfd-base",
			Syscall:      "utimensat",
			Comm:         "ioworkload",
			FDAtLeast:    ptrTo(int32(1)),
			RetVal:       ptrTo(int64(0)),
			IsError:      ptrTo(false),
		},
	})
}

// TestOpenOpenat2 exercises the raw openat2(2) syscall. openat2 differs from
// open/openat in that its flags/mode live inside an open_how struct (args[2]),
// not a plain int; the path is still at args[1]. This test verifies ior reads
// the path from args[1] and the real O_* word through the struct pointer rather
// than reporting the -1 unknown sentinel.
func TestOpenOpenat2(t *testing.T) {
	runScenario(t, "open-openat2", []ExpectedEvent{
		{
			PathContains: "openat2file.txt",
			Tracepoint:   "enter_openat2",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CREAT,
				Clear:      syscall.O_APPEND | syscall.O_TRUNC,
			},
		},
	})
}

func TestOpenCreat(t *testing.T) {
	runScenario(t, "open-creat", []ExpectedEvent{
		{
			PathContains: "creatfile.txt",
			Tracepoint:   "enter_creat",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_WRONLY),
				Set:        syscall.O_CREAT | syscall.O_TRUNC,
			},
		},
	})
}

func TestOpenByHandleAt(t *testing.T) {
	runScenario(t, "open-by-handle-at", []ExpectedEvent{
		{
			PathContains: "handlefile.txt",
			Tracepoint:   "enter_open_by_handle_at",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

// TestOpenByHandleAtCommFilterKeepsMatchingRows and
// TestOpenByHandleAtCommFilterDropsNonMatchingRows are the end-to-end guard for
// task e1: open_by_handle_at has no raw enter filter, so until
// handleOpenByHandleAtExit routed the pair through the full pair filter, NO
// filter dimension reached its rows and a -comm-filtered run emitted rows
// carrying a different comm. Both directions matter - the drop direction is the
// bug, the keep direction is the risk the fix carries.
func TestOpenByHandleAtCommFilterKeepsMatchingRows(t *testing.T) {
	runScenarioResultWithIorArgs(t, "open-by-handle-at", []ExpectedEvent{
		{
			PathContains: "handlefile.txt",
			Tracepoint:   "enter_open_by_handle_at",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, []string{"-comm", "ioworkload"})
}

func TestOpenByHandleAtCommFilterDropsNonMatchingRows(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "open-by-handle-at", nil,
		[]string{"-comm", "zzznotarealcomm"})
	for _, rec := range result.Records {
		t.Errorf("row survived -comm zzznotarealcomm: comm=%q tracepoint=%s path=%q",
			rec.Comm, rec.TraceID.String(), rec.Path)
	}
}

// TestOpenByHandleAtFailuresAreErrorRows is the end-to-end guard for task eq2:
// a failed open_by_handle_at used to be recycled in the exit handler, so it
// produced no row and no error count at all. The scenario fails the call with
// EBADF (mount_fd -1) and ESTALE (the file was unlinked after its handle was
// taken); each failure must be an error row named after the file its handle
// was taken of, with no descriptor.
//
// The third failure is the task k03 case: the handle that fails is not the
// thread's latest. There is no descriptor to look at for a failed call, so the
// per-thread stash named that row after the newer file.
func TestOpenByHandleAtFailuresAreErrorRows(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "open-by-handle-at-fail", defaultDuration, nil, nil)
	ebadf := func(file string) ExpectedRow {
		return ExpectedRow{
			FileContains: file,
			Syscall:      "open_by_handle_at",
			Comm:         "ioworkload",
			RetVal:       ptrTo(-int64(syscall.EBADF)),
			IsError:      ptrTo(true),
			FD:           ptrTo(int32(-1)),
		}
	}
	estale := ebadf("handle-estale-")
	estale.RetVal = ptrTo(-int64(syscall.ESTALE))
	AssertRowsPresent(t, rows, []ExpectedRow{ebadf("handle-ebadf.txt"), estale, ebadf("handle-older.txt")})
	assertNoHandleRowNamed(t, rows, "handle-newer.txt")
}

// handleRows returns the open_by_handle_at rows of a recording.
func handleRows(rows []iorparquet.Record) []iorparquet.Record {
	var out []iorparquet.Record
	for _, row := range rows {
		if row.Syscall == "open_by_handle_at" {
			out = append(out, row)
		}
	}
	return out
}

// assertNoHandleRowNamed fails for every open_by_handle_at row whose file
// contains unwanted.
func assertNoHandleRowNamed(t *testing.T, rows []iorparquet.Record, unwanted string) {
	t.Helper()
	for _, row := range handleRows(rows) {
		if strings.Contains(row.File, unwanted) {
			t.Errorf("open_by_handle_at row (tid=%d fd=%d ret=%d) is named %q, which is not the file of its handle",
				row.TID, row.FD, row.Ret, row.File)
		}
	}
}

// TestOpenByHandleAtIsNamedByItsHandleNotItsNumber is the end-to-end guard
// for task k03. The scenario closes each handle-opened descriptor and at once
// reopens the number with another file (the decoy), with the same flags, and
// keeps it open: exactly what /proc/<pid>/fd shows when ior handles the exit
// record. Every open_by_handle_at row must still be named after the file its
// handle belongs to. Before the handle bytes were captured every one of them
// was named after the decoy.
func TestOpenByHandleAtIsNamedByItsHandleNotItsNumber(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "open-by-handle-at-reuse", defaultDuration, nil, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{{
		FileContains:  "handle-reuse-",
		Syscall:       "open_by_handle_at",
		Comm:          "ioworkload",
		RetValAtLeast: ptrTo(int64(0)),
		IsError:       ptrTo(false),
	}})
	for _, row := range handleRows(rows) {
		if !strings.Contains(row.File, "handle-reuse-") {
			t.Errorf("open_by_handle_at row (fd=%d) is named %q, want its handle's file", row.FD, row.File)
		}
	}
}

// TestOpenByHandleAtMatchesAHandleTakenOnAnotherThread: the scenario takes
// each handle on one thread and opens it on another, once failing (EBADF) and
// once for real. Both rows belong to a thread that never called
// name_to_handle_at and must be named after the handle's file all the same.
func TestOpenByHandleAtMatchesAHandleTakenOnAnotherThread(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "open-by-handle-at-threads", defaultDuration, nil, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains: "handle-thread-",
			Syscall:      "open_by_handle_at",
			Comm:         "ioworkload",
			RetVal:       ptrTo(-int64(syscall.EBADF)),
			IsError:      ptrTo(true),
			FD:           ptrTo(int32(-1)),
		},
		{
			FileContains:  "handle-thread-",
			Syscall:       "open_by_handle_at",
			Comm:          "ioworkload",
			RetValAtLeast: ptrTo(int64(0)),
			IsError:       ptrTo(false),
		},
	})
	for _, row := range handleRows(rows) {
		if !strings.Contains(row.File, "handle-thread-") {
			t.Errorf("open_by_handle_at row (tid=%d ret=%d) is named %q, want its handle's file",
				row.TID, row.Ret, row.File)
		}
	}
}

func TestOpenEnoent(t *testing.T) {
	runParquetErrorScenario(t, "open-enoent", syscall.ENOENT, ExpectedRow{
		FileContains: "enoentfile.txt",
		Syscall:      "openat",
	}, nil)
}

func TestOpenRdonlyWrite(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "open-rdonly-write", defaultDuration, nil, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains:  "rdonlyfile.txt",
			Syscall:       "openat",
			Comm:          "ioworkload",
			RetValAtLeast: ptrTo(int64(1)),
			IsError:       ptrTo(false),
		},
		{
			FileContains: "rdonlyfile.txt",
			Syscall:      "write",
			Comm:         "ioworkload",
			FDAtLeast:    ptrTo(int32(1)),
			RetVal:       ptrTo(-int64(syscall.EBADF)),
			IsError:      ptrTo(true),
		},
	})
}

func TestOpenPidFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.Run("open-pid-filter", defaultDuration)
	if err != nil {
		t.Fatalf("run scenario open-pid-filter: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")

	// Parent's file should be captured.
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			PathContains: "parentfile.txt",
			Tracepoint:   "enter_openat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})

	// Child's file should NOT be captured (different PID).
	// Scope to openat so parent cleanup unlink/rmdir operations on childfile
	// do not create false positives.
	AssertEventsAbsent(t, result, []ExpectedEvent{
		{
			PathContains: "childfile.txt",
			Tracepoint:   "enter_openat",
		},
	})
}

func TestOpenDurationGap(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.Run("open-duration-gap", defaultDuration)
	if err != nil {
		t.Fatalf("run scenario open-duration-gap: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")

	// We intentionally sleep 800ms between first and second openat.
	const minGapNs = uint64(500 * 1_000_000)

	var (
		found  bool
		maxGap uint64
	)
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), "enter_openat") {
			continue
		}
		if !strings.Contains(rec.Path, "gap-shared.txt") {
			continue
		}
		found = true
		if rec.Cnt.DurationToPrev > maxGap {
			maxGap = rec.Cnt.DurationToPrev
		}
	}

	if !found {
		t.Fatalf("did not find openat record for gap-shared.txt")
	}
	if maxGap < minGapNs {
		t.Fatalf("max durationToPrev for openat gap-shared.txt = %d ns, want >= %d ns", maxGap, minGapNs)
	}
}
