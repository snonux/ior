package integrationtests

import (
	"strings"
	"syscall"
	"testing"

	iorparquet "ior/internal/parquet"
)

func TestCloseBasic(t *testing.T) {
	runScenario(t, "close-basic", []ExpectedEvent{
		{
			PathContains: "closefile-",
			Tracepoint:   "enter_close",
			Comm:         "ioworkload",
			MinCount:     3,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CREAT,
			},
		},
	})
}

func TestCloseRange(t *testing.T) {
	runScenario(t, "close-range", []ExpectedEvent{
		{
			PathContains: "closerangefile-",
			Tracepoint:   "enter_close_range",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
			},
		},
	})
}

func TestCloseRangeBounded(t *testing.T) {
	runScenario(t, "close-range-bounded", []ExpectedEvent{
		{
			PathContains: "closerangelow-",
			Tracepoint:   "enter_close_range",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
			},
		},
		{
			PathContains: "closerangehigh.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestCloseRangeCloexec(t *testing.T) {
	runScenario(t, "close-range-cloexec", []ExpectedEvent{
		{
			PathContains: "closerangecloexec-low-",
			Tracepoint:   "enter_close_range",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC,
			},
		},
		{
			PathContains: "closerangecloexec-low-",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     3,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC,
			},
		},
		{
			PathContains: "closerangecloexec-high.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Clear:      syscall.O_CLOEXEC,
			},
		},
	})
}

func TestCloseInvalidFd(t *testing.T) {
	runParquetErrorScenario(t, "close-invalid-fd", syscall.EBADF, ExpectedRow{
		Syscall: "close",
		FD:      ptrTo(int32(99999)),
	}, nil)
}

func TestCloseDoubleClose(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "close-double-close", defaultDuration, nil, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains: "doubleclosefile.txt",
			Syscall:      "close",
			Comm:         "ioworkload",
			RetVal:       ptrTo(int64(0)),
			IsError:      ptrTo(false),
		},
		{
			Syscall: "close",
			Comm:    "ioworkload",
			RetVal:  ptrTo(-int64(syscall.EBADF)),
			IsError: ptrTo(true),
		},
	})
}

func TestCloseRangeEmpty(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "close-range-empty", defaultDuration, nil, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{{
		Syscall: "close_range",
		Comm:    "ioworkload",
		FD:      ptrTo(int32(9000)),
		RetVal:  ptrTo(int64(0)),
		IsError: ptrTo(false),
	}})
}

// TestCloseUntrackedNeverNamesTheReusingFile is task jr2 end to end. The
// workload opens 64 files before ior attaches, so ior's fd table does not know
// them, then closes each one and immediately creates a pipe that takes the
// same number. ior used to label such a close by reading /proc/<pid>/fd after
// the close, which named the reusing pipe (or nothing). A close row may only
// carry what ior learned before the close: the first file was written to
// first, which resolves and caches its name, so its close is named; the
// others are unnamed unless a write cached their name before the close, and
// none may be named after a pipe.
//
// Each of the others is also written to right before its close. That write
// row is mostly processed after the close and the pipe, so its procfs read
// caches the pipe; only the read-time stamp keeps the close row from
// repeating it (with the stamp check removed, 62 of 63 such closes were named
// after the pipe, 5 of 5 runs). When ior happens to process the write before
// the close, the read caches the real file and the close row is correctly
// named after it (3 runs: 62-63 of 63 unnamed, 1-2 named closeuntracked-N.txt),
// so the test does not demand that these rows be unnamed.
func TestCloseUntrackedNeverNamesTheReusingFile(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "close-untracked", defaultDuration, nil, nil)
	assertCloseUntrackedRows(t, rows)
}

// assertCloseUntrackedRows checks the rows of a close-untracked run: the close
// of the first file is named, all 64 closes have a row, and none is named
// after the pipe that reused its number.
func assertCloseUntrackedRows(t *testing.T, rows []iorparquet.Record) {
	t.Helper()
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains: "closeuntracked-0.txt",
			Syscall:      "close",
			Comm:         "ioworkload",
			RetVal:       ptrTo(int64(0)),
		},
		{
			Syscall:  "close",
			Comm:     "ioworkload",
			RetVal:   ptrTo(int64(0)),
			MinCount: 64,
		},
	})
	for _, row := range rows {
		if row.Syscall == "close" && strings.Contains(row.File, "pipe") {
			t.Errorf("close of fd %d is named after the pipe that reused the number: %q", row.FD, row.File)
		}
	}
}
