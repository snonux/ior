//go:build amd64

package types

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Every traced syscall has its number: the event loop recognises a call a
// seccomp filter trapped by it (TraceId.SyscallNumber), and a syscall missing
// from the table would silently never be recognised.
func TestEveryTracedSyscallHasItsNumber(t *testing.T) {
	for id, tracepoint := range traceId2String {
		if _, known := id.SyscallNumber(); !known {
			t.Errorf("%s (id %d) has no syscall number in syscallNumbers", tracepoint, id)
		}
	}
	if len(syscallNumbers) == 0 {
		t.Fatal("syscallNumbers is empty")
	}
	if nr, known := TraceId(0).SyscallNumber(); known {
		t.Fatalf("an unknown trace ID has syscall number %d", nr)
	}
}

// The numbers are the x86_64 ones, for the enter and the exit tracepoint
// alike, and follow the kernel's names where they differ from libc's.
func TestSyscallNumbersAreTheX8664Ones(t *testing.T) {
	for id, want := range map[TraceId]int64{
		SYS_ENTER_READ:              unix.SYS_READ,
		SYS_EXIT_READ:               unix.SYS_READ,
		SYS_EXIT_WRITE:              unix.SYS_WRITE,
		SYS_EXIT_OPENAT:             unix.SYS_OPENAT,
		SYS_EXIT_FCHMOD:             unix.SYS_FCHMOD,
		SYS_EXIT_NEWSTAT:            unix.SYS_STAT,
		SYS_EXIT_NEWFSTATAT:         unix.SYS_NEWFSTATAT,
		SYS_EXIT_NEWUNAME:           unix.SYS_UNAME,
		SYS_EXIT_SENDFILE64:         unix.SYS_SENDFILE,
		SYS_EXIT_UMOUNT:             unix.SYS_UMOUNT2,
		SYS_EXIT_SCHED_GETSCHEDULER: unix.SYS_SCHED_GETSCHEDULER,
		SYS_EXIT_SCHED_GETAFFINITY:  unix.SYS_SCHED_GETAFFINITY,
		SYS_EXIT_SCHED_GETPARAM:     unix.SYS_SCHED_GETPARAM,
		SYS_EXIT_IO_URING_ENTER:     unix.SYS_IO_URING_ENTER,
		SYS_EXIT_PIDFD_SEND_SIGNAL:  unix.SYS_PIDFD_SEND_SIGNAL,
		SYS_EXIT_LANDLOCK_ADD_RULE:  unix.SYS_LANDLOCK_ADD_RULE,
		SYS_EXIT_PROCESS_VM_WRITEV:  unix.SYS_PROCESS_VM_WRITEV,
		SYS_EXIT_COPY_FILE_RANGE:    unix.SYS_COPY_FILE_RANGE,
		SYS_EXIT_NAME_TO_HANDLE_AT:  unix.SYS_NAME_TO_HANDLE_AT,
		SYS_EXIT_RESTART_SYSCALL:    unix.SYS_RESTART_SYSCALL,
	} {
		if got, known := id.SyscallNumber(); !known || got != want {
			t.Errorf("%s: SyscallNumber() = %d, %v, want %d", id, got, known, want)
		}
	}
}
