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
	}
	return nil
}

func callClockNanosleep(requestedNs int64) error {
	req := unix.Timespec{Sec: requestedNs / 1_000_000_000, Nsec: requestedNs % 1_000_000_000}
	_, _, errno := syscall.RawSyscall6(
		unix.SYS_CLOCK_NANOSLEEP,
		uintptr(unix.CLOCK_MONOTONIC),
		0,
		uintptr(unsafe.Pointer(&req)),
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

