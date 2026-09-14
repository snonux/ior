package integrationtests

import (
	"syscall"
	"testing"
)

func TestCopyFileRangeBasic(t *testing.T) {
	result, _ := runScenarioResult(t, "copy-file-range-basic", []ExpectedEvent{
		{
			PathContains: "copyrangesrc.txt",
			Tracepoint:   "enter_copy_file_range",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})

	// copy_file_range is TRANSFER_CLASSIFIED: a successful call reports
	// ctx->ret > 0, the number of bytes copied from fd_in to fd_out. The
	// basic scenario copies exactly the 32-byte payload
	// ("copy_file_range integration data") in a single call, so the exit
	// byte count is deterministic and must equal 32. Locking in the exact
	// count guards the transfer attribution (FamilyFS, fd_in@args[0]).
	exp := ExpectedEvent{Tracepoint: "enter_copy_file_range", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, exp, 32)
	assertEventDurationPositive(t, result, exp)
}

func TestCopyFileRangeBadDstFd(t *testing.T) {
	runParquetErrorScenario(t, "copy-file-range-bad-dst-fd", syscall.EBADF, ExpectedRow{
		FileContains: "copyrangeebadfsrc.txt",
		Syscall:      "copy_file_range",
		Bytes:        ptrTo(uint64(0)),
	}, nil)
}
