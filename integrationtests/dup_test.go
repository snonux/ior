package integrationtests

import (
	"syscall"
	"testing"
)

func TestDupBasic(t *testing.T) {
	runScenario(t, "dup-basic", []ExpectedEvent{
		{
			PathContains: "dupfile.txt",
			Tracepoint:   "enter_dup",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "dupfile.txt",
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

func TestDupDup2(t *testing.T) {
	runScenario(t, "dup-dup2", []ExpectedEvent{
		{
			PathContains: "dup2file.txt",
			Tracepoint:   "enter_dup2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "dup2file.txt",
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

func TestDupDup3(t *testing.T) {
	runScenario(t, "dup-dup3", []ExpectedEvent{
		{
			PathContains: "dup3file.txt",
			Tracepoint:   "enter_dup3",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "dup3file.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC,
			},
		},
	})
}

func TestDupInvalidFd(t *testing.T) {
	runParquetErrorScenario(t, "dup-invalid-fd", syscall.EBADF, ExpectedRow{
		Syscall: "dup",
		FD:      ptrTo(int32(99999)),
	}, nil)
}

func TestDup2SameFd(t *testing.T) {
	runScenario(t, "dup2-same-fd", []ExpectedEvent{
		{
			PathContains: "dup2samefile.txt",
			Tracepoint:   "enter_dup2",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Clear:      syscall.O_CLOEXEC,
			},
		},
	})
}

func TestDup3InvalidFlags(t *testing.T) {
	runParquetErrorScenario(t, "dup3-invalid-flags", syscall.EINVAL, ExpectedRow{
		FileContains: "dup3flagsfile.txt",
		Syscall:      "dup3",
	}, nil)
}
