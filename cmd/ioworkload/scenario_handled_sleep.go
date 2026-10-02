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
// thread blocked in the call it is meant for (told by its request pointer,
// rawSleep.procState, not by the syscall number alone), the first call must
// fail with EINTR and the second must succeed. Both run on the main thread, which
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

	sleep := newRawSleep(unix.SYS_CLOCK_NANOSLEEP, handledSleepNs)
	interrupted := make(chan error, 1)
	go func() {
		err := waitBlockedIn(tid, sleep.procState(), "clock_nanosleep")
		if err == nil {
			err = unix.Tgkill(os.Getpid(), tid, syscall.SIGUSR1)
		}
		interrupted <- err
	}()
	errno := sleep.run()
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
	sleep := newRawSleep(unix.SYS_NANOSLEEP, handledStoppedSleepNs)
	stopped := make(chan error, 1)
	go func() {
		err := waitBlockedIn(tid, sleep.procState(), "nanosleep")
		if err == nil {
			err = stopper.stopAndContinue()
		}
		stopped <- err
	}()
	errno := sleep.run()
	err = <-stopped
	if errno != 0 {
		err = errors.Join(err, fmt.Errorf("nanosleep returned errno %d, want 0: no handler ran", errno))
	}
	return errors.Join(err, stopper.close())
}

// rawSleep is one relative sleep of the scenario: the syscall it goes through,
// clock_nanosleep (on CLOCK_MONOTONIC) or nanosleep, and its request. The
// request lives on the heap (newRawSleep returns the pointer, and the
// goroutine that watches /proc captures the rawSleep), so its address is fixed
// before the call is made and cannot move with the goroutine's stack. That
// address is what tells the scenario's call from any other sleep of the thread
// (procState).
type rawSleep struct {
	nr  uintptr
	req *unix.Timespec
}

// newRawSleep prepares a relative sleep of ns nanoseconds through the syscall
// nr (unix.SYS_CLOCK_NANOSLEEP or unix.SYS_NANOSLEEP).
func newRawSleep(nr uintptr, ns int64) *rawSleep {
	return &rawSleep{nr: nr, req: &unix.Timespec{Sec: ns / 1_000_000_000, Nsec: ns % 1_000_000_000}}
}

// procState is how /proc/<pid>/task/<tid>/syscall starts while the thread is
// blocked in this very call: the syscall number and its arguments up to the
// request pointer, each argument as the kernel prints it ("0x%lx"), e.g.
// "230 0x1 0x0 0xc000012120 " and "35 0xc000012130 ".
//
// The number alone would not do. The Go runtime's own usleep is a nanosleep
// (35) the main thread can make as well, so a waiter matching "35 " could send
// its signal while the thread sits in a runtime sleep; the stop would then hit
// the wrong call or none. The runtime's request is on a stack, never at the
// address of this heap object, so the pointer names the scenario's call.
// (clock_nanosleep is matched the same way, although the runtime makes none.)
func (s *rawSleep) procState() string {
	req := uintptr(unsafe.Pointer(s.req))
	if s.nr == unix.SYS_CLOCK_NANOSLEEP {
		return fmt.Sprintf("%d 0x%x 0x0 0x%x ", s.nr, unix.CLOCK_MONOTONIC, req)
	}
	return fmt.Sprintf("%d 0x%x ", s.nr, req)
}

// run issues the sleep and returns the errno the program observes. Syscall6,
// not RawSyscall6: the runtime hands the P to another thread while this one
// sleeps, so the helper goroutines run even with GOMAXPROCS=1.
func (s *rawSleep) run() syscall.Errno {
	var errno syscall.Errno
	if s.nr == unix.SYS_CLOCK_NANOSLEEP {
		_, _, errno = syscall.Syscall6(s.nr, uintptr(unix.CLOCK_MONOTONIC), 0, uintptr(unsafe.Pointer(s.req)), 0, 0, 0)
	} else {
		_, _, errno = syscall.Syscall6(s.nr, uintptr(unsafe.Pointer(s.req)), 0, 0, 0, 0, 0)
	}
	runtime.KeepAlive(s)
	return errno
}
