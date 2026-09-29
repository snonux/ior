package integrationtests

import (
	"syscall"
	"testing"
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
