package integrationtests

import (
	"syscall"
	"testing"
)

func TestTruncateBasic(t *testing.T) {
	runScenario(t, "truncate-basic", []ExpectedEvent{
		{
			PathContains: "truncfile.txt",
			Tracepoint:   "enter_truncate",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestTruncateFtruncate(t *testing.T) {
	runScenario(t, "truncate-ftruncate", []ExpectedEvent{
		{
			PathContains: "ftruncfile.txt",
			Tracepoint:   "enter_ftruncate",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestTruncateEnoent(t *testing.T) {
	runParquetErrorScenario(t, "truncate-enoent", syscall.ENOENT, ExpectedRow{
		FileContains: "truncate-enoent-missing.txt",
		Syscall:      "truncate",
	}, nil)
}

func TestTruncateFtruncateEbadf(t *testing.T) {
	runParquetErrorScenario(t, "truncate-ftruncate-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "ftruncate",
		FD:      ptrTo(int32(99999)),
	}, nil)
}
