package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// itimerspec mirrors struct itimerspec from <time.h> (it_interval, it_value).
// Used as the argument to timer_settime / timer_gettime.
type itimerspec struct {
	Interval unix.Timespec
	Value    unix.Timespec
}

// itimerval mirrors struct itimerval from <sys/time.h> (it_interval, it_value),
// each a struct timeval. It is the argument to setitimer/getitimer (the classic
// interval timers, distinct from the POSIX per-process timer_* family above).
type itimerval struct {
	Interval unix.Timeval
	Value    unix.Timeval
}

// itimerReal is ITIMER_REAL (=0): a real-time interval timer that, when armed,
// delivers SIGALRM on expiry.
const itimerReal = 0

// intervalTimerNoop exercises the classic interval-timer syscalls setitimer(2)
// and getitimer(2) without ever arming anything, so the enter_setitimer /
// enter_getitimer tracepoints fire end-to-end while remaining fully SIGNAL-SAFE.
//
// SAFETY: setitimer is called with an ALL-ZERO struct itimerval. A zero it_value
// disarms the timer and arms nothing new, so NO SIGALRM is ever scheduled or
// delivered — this mirrors the alarm(0) pattern in miscAlarmCancel and the
// far-future / never-firing approach in posixTimerLifecycle. getitimer is a pure
// read of the (now disarmed) timer's state.
//
// Both setitimer and getitimer are KindNull (null_event) on enter and return an
// UNCLASSIFIED ret_event on exit: neither takes a pathname nor an fd, and the
// return value is not a descriptor. We therefore only assert enter-presence.
func intervalTimerNoop() error {
	// All-zero itimerval: it_interval = it_value = {0,0}. This disarms
	// ITIMER_REAL and arms nothing, so no SIGALRM can fire.
	var zero itimerval
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_SETITIMER,
		itimerReal,
		uintptr(unsafe.Pointer(&zero)),
		0, // old_value == NULL (we don't care about the previous setting)
	); errno != 0 {
		return fmt.Errorf("setitimer: %w", errno)
	}

	// getitimer reads the current (disarmed) ITIMER_REAL state into out; a safe,
	// side-effect-free read included for symmetry with setitimer.
	var out itimerval
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_GETITIMER,
		itimerReal,
		uintptr(unsafe.Pointer(&out)),
		0,
	); errno != 0 {
		return fmt.Errorf("getitimer: %w", errno)
	}

	return nil
}

// posixTimerLifecycle exercises the full POSIX per-process timer family so the
// tracer's null_event handling is covered end-to-end:
//
//	timer_create -> timer_settime -> timer_gettime -> timer_getoverrun -> timer_delete
//
// These are deliberately distinct from timerfd_create: timer_create returns a
// timer_t through an OUTPUT pointer (args[2]), NOT a file descriptor, so the
// tracer must emit a null_event for it and must never treat any argument or the
// return value as an fd (contrast with timerfd_create, which is an fd-returning
// eventfd-family syscall). See man 2 timer_create.
func posixTimerLifecycle() error {
	// timer_t (__kernel_timer_t) is an int in the Linux UAPI, not an fd.
	var timerID int32

	// timer_create(CLOCK_MONOTONIC, NULL, &timerID): a NULL sigevent requests
	// the default notification (SIGALRM via signal), and timerID is the output
	// timer_t — not an fd.
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_TIMER_CREATE,
		uintptr(unix.CLOCK_MONOTONIC),
		0, // sevp == NULL
		uintptr(unsafe.Pointer(&timerID)),
	); errno != 0 {
		return fmt.Errorf("timer_create: %w", errno)
	}

	// Arm the timer with a far-future one-shot expiry so it never actually
	// fires during the test; we only care about the syscalls being traced.
	newValue := itimerspec{
		Value: unix.Timespec{Sec: 3600, Nsec: 0},
	}
	if _, _, errno := syscall.RawSyscall6(
		unix.SYS_TIMER_SETTIME,
		uintptr(timerID),
		0, // flags (relative)
		uintptr(unsafe.Pointer(&newValue)),
		0, // old_value == NULL
		0, 0,
	); errno != 0 {
		return fmt.Errorf("timer_settime: %w", errno)
	}

	var curValue itimerspec
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_TIMER_GETTIME,
		uintptr(timerID),
		uintptr(unsafe.Pointer(&curValue)),
		0,
	); errno != 0 {
		return fmt.Errorf("timer_gettime: %w", errno)
	}

	if _, _, errno := syscall.RawSyscall(
		unix.SYS_TIMER_GETOVERRUN,
		uintptr(timerID),
		0, 0,
	); errno != 0 {
		return fmt.Errorf("timer_getoverrun: %w", errno)
	}

	if _, _, errno := syscall.RawSyscall(
		unix.SYS_TIMER_DELETE,
		uintptr(timerID),
		0, 0,
	); errno != 0 {
		return fmt.Errorf("timer_delete: %w", errno)
	}

	return nil
}
