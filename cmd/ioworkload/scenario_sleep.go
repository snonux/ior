package main

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const sleepSyscallsEmitFor = 2 * time.Second

func sleepSyscalls() error {
	deadline := time.Now().Add(sleepSyscallsEmitFor)
	for time.Now().Before(deadline) {
		if err := syscall.Nanosleep(&syscall.Timespec{Sec: 0, Nsec: 2_000_000}, nil); err != nil && err != syscall.EINTR {
			return fmt.Errorf("nanosleep: %w", err)
		}
		if err := callClockNanosleep(3_000_000); err != nil {
			return err
		}
		// Also exercise the TIMER_ABSTIME (absolute) path so the tracer's
		// absolute-sleep handling is covered: the request timespec here is an
		// absolute CLOCK_MONOTONIC wakeup time, not a relative duration, so the
		// tracer must NOT report it as a sleep duration (see task a20).
		if err := callClockNanosleepAbs(2_000_000); err != nil {
			return err
		}
	}
	return nil
}

// callClockNanosleep issues a relative clock_nanosleep (flags = 0), sleeping for
// requestedNs nanoseconds.
func callClockNanosleep(requestedNs int64) error {
	req := unix.Timespec{Sec: requestedNs / 1_000_000_000, Nsec: requestedNs % 1_000_000_000}
	return invokeClockNanosleep(0, &req)
}

// callClockNanosleepAbs issues an absolute clock_nanosleep (flags =
// TIMER_ABSTIME). The request timespec is an absolute CLOCK_MONOTONIC wakeup
// time computed as "now + aheadNs", so the call blocks for roughly aheadNs but
// the request value itself is a multi-decade absolute timestamp, not a
// duration.
func callClockNanosleepAbs(aheadNs int64) error {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return fmt.Errorf("clock_gettime: %w", err)
	}
	target := now.Nano() + aheadNs
	req := unix.Timespec{Sec: target / 1_000_000_000, Nsec: target % 1_000_000_000}
	return invokeClockNanosleep(unix.TIMER_ABSTIME, &req)
}

// invokeClockNanosleep is the shared raw clock_nanosleep syscall wrapper used by
// both the relative and absolute callers.
func invokeClockNanosleep(flags uintptr, req *unix.Timespec) error {
	_, _, errno := syscall.RawSyscall6(
		unix.SYS_CLOCK_NANOSLEEP,
		uintptr(unix.CLOCK_MONOTONIC),
		flags,
		uintptr(unsafe.Pointer(req)),
		0,
		0,
		0,
	)
	runtime.KeepAlive(req)
	if errno != 0 && errno != syscall.EINTR {
		return fmt.Errorf("clock_nanosleep: %w", errno)
	}
	return nil
}

