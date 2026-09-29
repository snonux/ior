package integrationtests

import (
	"syscall"
	"testing"
)

func TestFcntlDupfd(t *testing.T) {
	runScenario(t, "fcntl-dupfd", []ExpectedEvent{
		{
			PathContains: "fcntlfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "fcntlfile.txt",
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

func TestFcntlSetfl(t *testing.T) {
	runScenario(t, "fcntl-setfl", []ExpectedEvent{
		{
			PathContains: "fcntlsetflfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Clear:      syscall.O_CREAT | syscall.O_APPEND,
			},
		},
		{
			PathContains: "fcntlsetflfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_APPEND,
				Clear:      syscall.O_CREAT,
			},
		},
		{
			PathContains: "fcntlsetflfile.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_APPEND,
				Clear:      syscall.O_CREAT,
			},
		},
	})
}

func TestFcntlSetfd(t *testing.T) {
	runScenario(t, "fcntl-setfd", []ExpectedEvent{
		{
			PathContains: "fcntlsetfdfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC,
			},
		},
		{
			PathContains: "fcntlsetfdfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     2,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Clear:      syscall.O_CLOEXEC,
			},
		},
		{
			PathContains: "fcntlsetfdfile.txt",
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

func TestFcntlDupfdCloexec(t *testing.T) {
	runScenario(t, "fcntl-dupfd-cloexec", []ExpectedEvent{
		{
			PathContains: "fcntlcloexecfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "fcntlcloexecfile.txt",
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

func TestFcntlInvalidFd(t *testing.T) {
	runParquetErrorScenario(t, "fcntl-invalid-fd", syscall.EBADF, ExpectedRow{
		Syscall: "fcntl",
		FD:      ptrTo(int32(99999)),
	}, nil)
}

func TestFcntlDupfdMax(t *testing.T) {
	runParquetErrorScenario(t, "fcntl-dupfd-max", syscall.EINVAL, ExpectedRow{
		FileContains: "fcntldupfdmaxfile.txt",
		Syscall:      "fcntl",
	}, nil)
}
