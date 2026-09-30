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
	// restartSignalDelay is how long the blocked call waits before a signal
	// interrupts it. It only has to exceed the time the worker needs to enter
	// the syscall; if the signal lands early the call simply is not blocked yet
	// and the scenario is a weaker (but still hang-free) exercise.
	restartSignalDelay = 150 * time.Millisecond

	// restartWriteDelay is how long after the signal the pipe becomes readable,
	// so the restarted read has to block a second time before it completes.
	restartWriteDelay = 150 * time.Millisecond

	// restartSleepNs is the relative clock_nanosleep request. It is longer
	// than restartSignalDelay, so the signal is what ends the sleep.
	restartSleepNs = 2_000_000_000
)

// signalRestart makes signals interrupt blocking syscalls so the tracer sees
// the kernel-internal restart codes at sys_exit (task aq2):
//
//   - read on an empty pipe gets -ERESTARTSYS (-512). The Go runtime installs
//     every handler with SA_RESTART, so user space never sees the code: the
//     kernel re-executes the read (a second sys_enter) and it later returns
//     the byte the workload writes.
//   - a relative clock_nanosleep gets -ERESTART_RESTARTBLOCK (-516). A handled
//     signal turns this into EINTR for the caller (the restart_syscall path is
//     only taken when no handler runs, e.g. SIGSTOP/SIGCONT).
//
// The signal is delivered with tgkill to the one OS thread that issues the
// blocking call, which is why the goroutine is pinned. SIGUSR1 goes through
// os/signal.Notify so the Go runtime installs a real handler and does not
// discard the signal.
func signalRestart() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGUSR1)
	defer signal.Stop(sigs)
	go func() {
		for range sigs { // drain; delivery to the handler is all that matters
		}
	}()

	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	tid := syscall.Gettid()
	if err := restartedRead(fds, tid); err != nil {
		return err
	}
	return interruptedSleep(tid)
}

// restartedRead blocks in read(2) on an empty pipe, has SIGUSR1 interrupt it,
// and then makes the data available so the restarted read completes with 1.
func restartedRead(fds [2]int, tid int) error {
	go func() {
		time.Sleep(restartSignalDelay)
		_ = unix.Tgkill(os.Getpid(), tid, syscall.SIGUSR1)
		time.Sleep(restartWriteDelay)
		_, _ = syscall.Write(fds[1], []byte{'x'})
	}()

	var buf [1]byte
	n, _, errno := syscall.RawSyscall(syscall.SYS_READ, uintptr(fds[0]),
		uintptr(unsafe.Pointer(&buf[0])), 1)
	if errno != 0 && errno != syscall.EINTR {
		return fmt.Errorf("read: %w", errno)
	}
	if errno == 0 && n != 1 {
		return fmt.Errorf("read: got %d bytes, want 1", n)
	}
	return nil
}

// interruptedSleep sleeps in clock_nanosleep and has SIGUSR1 cut it short;
// EINTR is the expected outcome and is not an error for the scenario.
func interruptedSleep(tid int) error {
	go func() {
		time.Sleep(restartSignalDelay)
		_ = unix.Tgkill(os.Getpid(), tid, syscall.SIGUSR1)
	}()
	err := callClockNanosleep(restartSleepNs)
	if err != nil && !errors.Is(err, syscall.EINTR) {
		return err
	}
	return nil
}
