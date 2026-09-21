package integrationtests

import (
	"strings"
	"syscall"
	"testing"
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
