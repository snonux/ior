package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	// and the scenario is a weaker exercise (the -512 row may be missing), but
	// it still terminates: the read is completed by the write that follows.
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
// blocking call, which is why the goroutine is pinned. The blocking read goes
// through syscall.Syscall (not RawSyscall) so the runtime hands the P to
// another thread while this one is blocked; the helper goroutines that send
// the signal and write the byte need a P, so with GOMAXPROCS=1 (or a single
// CPU) a RawSyscall would hang the scenario forever. SIGUSR1 goes through
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
	// Syscall, not RawSyscall: it enters the scheduler-aware syscall state so
	// sysmon retakes the P while the read blocks, letting the helper goroutine
	// above run even when GOMAXPROCS is 1.
	n, _, errno := syscall.Syscall(syscall.SYS_READ, uintptr(fds[0]),
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

const (
	// stopRestartSleepNs is the relative clock_nanosleep request of the
	// stop-restart scenario. It outlasts the stop, so the call is resumed and
	// still has time left to sleep after SIGCONT.
	stopRestartSleepNs = 600_000_000
	// stopRestartStopAfter and stopRestartStopFor are the stopper's timing,
	// in sh(1) sleep syntax: SIGSTOP 150ms into the sleep, SIGCONT 200ms
	// later. stopRestartLinger keeps the stopper alive until well after the
	// sleep ends, so its SIGCHLD (which the Go runtime handles) cannot
	// interrupt the sleep and turn the restart into EINTR.
	stopRestartStopAfter = "0.15"
	stopRestartStopFor   = "0.2"
	stopRestartLinger    = "1"
)

// stopRestart makes the kernel resume an interrupted sleep through
// restart_syscall (task fs2). A relative clock_nanosleep is stopped by
// SIGSTOP and continued by SIGCONT; neither has a handler (SIGSTOP cannot
// have one, and the Go runtime leaves SIGCONT at its default unless it is
// requested through os/signal), so the call exits with
// -ERESTART_RESTARTBLOCK (-516) and the kernel re-enters the thread via
// restart_syscall, which sleeps until the original deadline and returns 0.
// ior must report this as ONE clock_nanosleep row.
//
// A stopped process cannot continue itself, so the stopper is an external
// process: a child sh(1) signalling this pid. It is a separate process, so a
// -pid trace of the workload does not see its syscalls. The sleep runs on
// the main thread, which main.go's init() pins, so its tid is the pid.
func stopRestart() error {
	script := fmt.Sprintf("sleep %s; kill -STOP %d; sleep %s; kill -CONT %d; sleep %s",
		stopRestartStopAfter, os.Getpid(), stopRestartStopFor, os.Getpid(), stopRestartLinger)
	stopper := exec.Command("sh", "-c", script)
	if err := stopper.Start(); err != nil {
		return fmt.Errorf("start stopper: %w", err)
	}
	// Syscall6 (via invokeClockNanosleep), not RawSyscall: the runtime keeps
	// scheduling other goroutines while this thread sleeps.
	sleepErr := callClockNanosleep(stopRestartSleepNs)
	if err := stopper.Wait(); err != nil {
		return fmt.Errorf("stopper: %w", err)
	}
	return sleepErr
}

// stopRestartTwiceSleepNs is the relative clock_nanosleep request of the
// stop-restart-twice scenario. It only has to outlast two stopper handshakes
// (milliseconds each); the scenario fails when the sleep ends before the
// second stop found it.
const stopRestartTwiceSleepNs = 1_500_000_000

// stopRestartTwice has one sleep stopped and continued twice (task 203). The
// first SIGSTOP/SIGCONT ends the clock_nanosleep with -516 and the kernel
// resumes it through restart_syscall; the second one finds the thread inside
// that restart_syscall, which exits -516 in turn and is resumed by another
// restart_syscall. The program sees one sleep that returns 0. ior must report
// ONE clock_nanosleep row that counts two folded restarts.
//
// Nothing relies on timing: each stop is sent only once /proc shows the main
// thread blocked in the call it is meant for - the scenario's own
// clock_nanosleep (told by its request pointer, rawSleep.procState), then
// restart_syscall, which the thread can only be in while that sleep is being
// resumed - and the stopper reports back that it saw the thread stopped. The
// stopper stays alive until the sleep is over, so its SIGCHLD (which the Go
// runtime handles) cannot interrupt it. The sleep runs on the main thread,
// which main.go's init() pins, so its tid is the pid.
func stopRestartTwice() error {
	tid := syscall.Gettid()
	stopper, err := startStopper()
	if err != nil {
		return err
	}
	sleep := newRawSleep(unix.SYS_CLOCK_NANOSLEEP, stopRestartTwiceSleepNs)
	stopped := make(chan error, 1)
	go func() { stopped <- stopTwice(tid, sleep, stopper) }()
	errno := sleep.run()
	err = <-stopped
	if errno != 0 {
		err = errors.Join(err, fmt.Errorf("clock_nanosleep returned errno %d, want 0: no handler ran", errno))
	}
	return errors.Join(err, stopper.close())
}

// stopTwice stops and continues the thread tid once while it is blocked in
// sleep and once more while it is blocked in the restart_syscall that resumes
// it. /proc shows a thread resumed that way under restart_syscall's number,
// not the interrupted call's.
func stopTwice(tid int, sleep *rawSleep, stopper *reexecStopper) error {
	if err := waitBlockedIn(tid, sleep.procState(), "clock_nanosleep"); err != nil {
		return err
	}
	if err := stopper.stopAndContinue(); err != nil {
		return err
	}
	resumed := fmt.Sprintf("%d ", unix.SYS_RESTART_SYSCALL)
	if err := waitBlockedIn(tid, resumed, "restart_syscall"); err != nil {
		return err
	}
	return stopper.stopAndContinue()
}
