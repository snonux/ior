package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// handledSleepNs is the relative clock_nanosleep request a handled signal
	// cuts short. It only has to outlast the handshake that sends the signal;
	// the scenario fails when the sleep runs to its end.
	handledSleepNs = 3_000_000_000

	// handledStoppedSleepNs is the nanosleep(2) request of the later call, the
	// one that is stopped and continued. It outlasts the stopper's handshake,
	// so the kernel has something left to resume through restart_syscall.
	handledStoppedSleepNs = 1_000_000_000
)

// signalHandledSleep is the sequence task t13 is about: a sleep that a HANDLED
// signal ends, followed by another blocking call of the same thread that is
// stopped and continued.
//
//  1. A relative clock_nanosleep is interrupted by SIGUSR1, for which the Go
//     runtime runs its handler. The call exits -ERESTART_RESTARTBLOCK (-516)
//     and the program gets EINTR: with a handler, nothing resumes it.
//  2. A nanosleep(2) - another syscall than clock_nanosleep, so a trace of
//     clock_nanosleep and restart_syscall does not see it - is interrupted by
//     SIGSTOP/SIGCONT from an external stopper. No handler runs, so the kernel
//     resumes it through restart_syscall and the program sees it return 0.
//
// A tracer that records clock_nanosleep and restart_syscall only (the
// handler's rt_sigreturn and the nanosleep stay silent) sees the first sleep's
// -516 exit and then, as the thread's next record, the restart_syscall of the
// second call. That restart_syscall does not continue the first sleep, and ior
// must not report the two as one clock_nanosleep that returned 0.
//
// Nothing relies on timing: each signal is sent only once /proc shows the
// thread blocked in the call it is meant for, the first call must fail with
// EINTR and the second must succeed. Both run on the main thread, which
// main.go's init() pins, so its tid is the pid.
func signalHandledSleep() error {
	tid := syscall.Gettid()
	if err := handledSleep(tid); err != nil {
		return fmt.Errorf("handled sleep: %w", err)
	}
	if err := stoppedNanosleep(tid); err != nil {
		return fmt.Errorf("stopped nanosleep: %w", err)
	}
	return nil
}

// handledSleep blocks in clock_nanosleep and has SIGUSR1 cut it short once
// the thread is blocked there. os/signal.Notify makes the runtime keep the
// signal and run its handler; the sleep must return EINTR.
func handledSleep(tid int) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	defer signal.Stop(sigs)

	interrupted := make(chan error, 1)
	go func() {
		err := waitBlockedIn(tid, fmt.Sprintf("%d ", unix.SYS_CLOCK_NANOSLEEP), "clock_nanosleep")
		if err == nil {
			err = unix.Tgkill(os.Getpid(), tid, syscall.SIGUSR1)
		}
		interrupted <- err
	}()
	errno := rawSleep(unix.SYS_CLOCK_NANOSLEEP, handledSleepNs)
	if err := <-interrupted; err != nil {
		return err
	}
	if errno != syscall.EINTR {
		return fmt.Errorf("clock_nanosleep returned errno %d, want EINTR: the handled signal did not cut it", errno)
	}
	// The runtime forwards the signal from its handler: the handler ran.
	select {
	case <-sigs:
		return nil
	case <-time.After(reexecHandshakeTimeout):
		return errors.New("SIGUSR1 was never handled")
	}
}

// stoppedNanosleep blocks in nanosleep(2) and has the external stopper send
// SIGSTOP and SIGCONT once the thread is blocked there. The call must return
// 0: the kernel resumed it. The stopper stays alive until the sleep is over,
// so its SIGCHLD (which the Go runtime handles) cannot interrupt it.
func stoppedNanosleep(tid int) error {
	stopper, err := startStopper()
	if err != nil {
		return err
	}
	stopped := make(chan error, 1)
	go func() {
		err := waitBlockedIn(tid, fmt.Sprintf("%d ", unix.SYS_NANOSLEEP), "nanosleep")
		if err == nil {
			err = stopper.stopAndContinue()
		}
		stopped <- err
	}()
	errno := rawSleep(unix.SYS_NANOSLEEP, handledStoppedSleepNs)
	err = <-stopped
	if errno != 0 {
		err = errors.Join(err, fmt.Errorf("nanosleep returned errno %d, want 0: no handler ran", errno))
	}
	return errors.Join(err, stopper.close())
}

// rawSleep issues a relative sleep of ns nanoseconds through the syscall nr,
// clock_nanosleep (on CLOCK_MONOTONIC) or nanosleep, and returns the errno the
// program observes. Syscall6, not RawSyscall6: the runtime hands the P to
// another thread while this one sleeps, so the helper goroutines run even
// with GOMAXPROCS=1.
func rawSleep(nr uintptr, ns int64) syscall.Errno {
	req := unix.Timespec{Sec: ns / 1_000_000_000, Nsec: ns % 1_000_000_000}
	var errno syscall.Errno
	if nr == unix.SYS_CLOCK_NANOSLEEP {
		_, _, errno = syscall.Syscall6(nr, uintptr(unix.CLOCK_MONOTONIC), 0, uintptr(unsafe.Pointer(&req)), 0, 0, 0)
	} else {
		_, _, errno = syscall.Syscall6(nr, uintptr(unsafe.Pointer(&req)), 0, 0, 0, 0, 0)
	}
	runtime.KeepAlive(&req)
	return errno
}
