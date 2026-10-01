package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// reexecReadFd is the descriptor the scenario's blocking reads use: the
	// pipe's read end moved to a fixed number, so a test can tell these reads
	// from every other read the main thread makes (os/exec's status pipe, ...).
	reexecReadFd = 200

	// The three reads ask for different byte counts, so their final rows are
	// told apart by the return value.
	reexecStopBytes    = 1 // interrupted by SIGSTOP/SIGCONT: no handler
	reexecRestartBytes = 2 // interrupted by a handler with SA_RESTART
	reexecEINTRBytes   = 3 // interrupted by a handler without SA_RESTART

	// reexecHandshakeTimeout bounds every wait for the other side. It is a
	// failure bound, not a delay: each step proceeds as soon as its condition
	// holds.
	reexecHandshakeTimeout = 20 * time.Second

	// saRestart is SA_RESTART (include/uapi/asm-generic/signal-defs.h).
	saRestart = 0x10000000
)

// signalReexec interrupts a blocking read(2) three times, once for each way
// the kernel can deal with -ERESTARTSYS (task 103):
//
//  1. SIGSTOP/SIGCONT from an external stopper: no handler runs, the kernel
//     re-executes the read. The program sees one read returning 1 byte.
//  2. SIGUSR1 with the Go runtime's handler, which is installed with
//     SA_RESTART: the handler runs, then the kernel re-executes the read. The
//     program sees one read returning 2 bytes.
//  3. SIGUSR2 with the same handler but SA_RESTART cleared: the program gets
//     EINTR and retries by itself. The program made two reads: one that
//     failed with EINTR (-512 at sys_exit) and one returning 3 bytes. This is
//     the negative control: ior must keep them apart.
//
// Nothing here relies on timing. A helper goroutine sends each signal only
// after /proc shows the reading thread blocked inside the read, and makes the
// pipe readable only after it has proof the signal was taken (the stopper's
// report, or the runtime forwarding the signal), so every read is interrupted
// exactly as described and each phase checks what the program observed.
//
// The reads run on the main thread, which main.go's init() pins, so its tid
// is the pid; the helper goroutines run on other threads.
func signalReexec() error {
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[1])
	if err := unix.Dup3(fds[0], reexecReadFd, unix.O_CLOEXEC); err != nil {
		return fmt.Errorf("dup3: %w", err)
	}
	defer syscall.Close(reexecReadFd)
	if err := syscall.Close(fds[0]); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	tid := syscall.Gettid()
	if err := stoppedRead(fds[1], tid); err != nil {
		return fmt.Errorf("stopped read: %w", err)
	}
	if err := handledRead(fds[1], tid, syscall.SIGUSR1, true, reexecRestartBytes); err != nil {
		return fmt.Errorf("SA_RESTART read: %w", err)
	}
	if err := handledRead(fds[1], tid, syscall.SIGUSR2, false, reexecEINTRBytes); err != nil {
		return fmt.Errorf("EINTR read: %w", err)
	}
	return nil
}

// stoppedRead blocks in a read that an external stopper interrupts with
// SIGSTOP and SIGCONT. A stopped process cannot continue itself, so the
// stopper is a child sh(1), as in the stop-restart scenario; it is a separate
// process, so a -pid trace of the workload does not see its syscalls. It acts
// when told to and reports back, and it stays alive until the read is done so
// that its SIGCHLD (which the Go runtime handles) cannot interrupt the read.
func stoppedRead(writeFd, tid int) error {
	stopper := exec.Command("sh", "-c", stopperScript(os.Getpid()))
	stdin, err := stopper.StdinPipe()
	if err != nil {
		return fmt.Errorf("stopper stdin: %w", err)
	}
	stdout, err := stopper.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stopper stdout: %w", err)
	}
	if err := stopper.Start(); err != nil {
		return fmt.Errorf("start stopper: %w", err)
	}

	interrupted := interruptAndFeed(writeFd, tid, reexecStopBytes, func() error {
		if _, err := stdin.Write([]byte("go\n")); err != nil {
			return fmt.Errorf("signal stopper: %w", err)
		}
		// "stopped" means the stopper saw the main thread in a group stop,
		// which a thread only enters on its way out of the interrupted
		// syscall: the read did exit with a restart code.
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "stopped" {
			return fmt.Errorf("stopper reported %q, want \"stopped\": %v", line, err)
		}
		return nil
	})
	eintrs, readErr := blockingRead(reexecStopBytes)
	err = errors.Join(readErr, <-interrupted)
	if eintrs != 0 {
		err = errors.Join(err, fmt.Errorf("read saw EINTR %d times, want none: no handler ran", eintrs))
	}
	// Closing stdin lets the stopper's final read return and the shell exit.
	return errors.Join(err, stdin.Close(), stopper.Wait())
}

// stopperScript is the stopper's program: wait for the go-ahead on stdin,
// stop the workload, wait until the kernel reports its main thread stopped
// (bounded, so a stop that never shows cannot hang the scenario), continue
// it, report whether the stop was seen, and linger until stdin closes.
func stopperScript(pid int) string {
	return fmt.Sprintf(`read go || exit 1
kill -STOP %[1]d
seen=timeout
i=0
while [ $i -lt 5000 ]; do
	if grep -q '^State:[[:space:]]*T' /proc/%[1]d/status; then seen=stopped; break; fi
	i=$((i+1))
done
kill -CONT %[1]d
echo $seen
read bye
exit 0`, pid)
}

// handledRead blocks in a read that sig interrupts on this thread. The Go
// runtime's handler runs for it (os/signal.Notify makes the runtime keep the
// signal instead of discarding it); with restart false SA_RESTART is cleared
// from that handler first, so the program gets EINTR and has to retry.
func handledRead(writeFd, tid int, sig syscall.Signal, restart bool, n int) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, sig)
	defer signal.Stop(sigs)
	if !restart {
		if err := clearSARestart(sig); err != nil {
			return err
		}
	}

	interrupted := interruptAndFeed(writeFd, tid, n, func() error {
		if err := unix.Tgkill(os.Getpid(), tid, sig); err != nil {
			return fmt.Errorf("tgkill: %w", err)
		}
		// The runtime forwards the signal from its handler: once it arrives
		// here the handler has run, i.e. the blocked read was interrupted.
		select {
		case <-sigs:
			return nil
		case <-time.After(reexecHandshakeTimeout):
			return fmt.Errorf("signal %d was never handled", sig)
		}
	})
	eintrs, readErr := blockingRead(n)
	err := errors.Join(readErr, <-interrupted)
	wantEINTR := 1
	if restart {
		wantEINTR = 0
	}
	if eintrs != wantEINTR {
		err = errors.Join(err, fmt.Errorf("read saw EINTR %d times, want %d", eintrs, wantEINTR))
	}
	return err
}

// interruptAndFeed starts the helper of one phase: once the thread tid is
// blocked in the scenario's read it runs interrupt, and then makes n bytes
// readable. The bytes are written even when a step failed, so the reader is
// never left blocked; the channel delivers the helper's error.
func interruptAndFeed(writeFd, tid, n int, interrupt func() error) <-chan error {
	done := make(chan error, 1)
	go func() {
		err := waitBlockedInRead(tid)
		if err == nil {
			err = interrupt()
		}
		if _, werr := syscall.Write(writeFd, make([]byte, n)); werr != nil {
			err = errors.Join(err, fmt.Errorf("write: %w", werr))
		}
		done <- err
	}()
	return done
}

// blockingRead reads n bytes from the scenario's pipe, retrying after EINTR
// like any C read loop, and returns how often it saw EINTR.
func blockingRead(n int) (eintrs int, err error) {
	buf := make([]byte, n)
	for {
		// Syscall, not RawSyscall: the runtime hands the P to another thread
		// while this one is blocked, so the helper goroutine runs even with
		// GOMAXPROCS=1.
		got, _, errno := syscall.Syscall(syscall.SYS_READ, reexecReadFd,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(n))
		switch {
		case errno == syscall.EINTR:
			eintrs++
		case errno != 0:
			return eintrs, fmt.Errorf("read: %w", errno)
		case int(got) != n:
			return eintrs, fmt.Errorf("read: got %d bytes, want %d", got, n)
		default:
			return eintrs, nil
		}
	}
}

// waitBlockedInRead returns once the thread tid sleeps inside read(2) on the
// scenario's descriptor. /proc/<pid>/task/<tid>/syscall shows the syscall
// number and arguments of a thread that is blocked in the kernel ("running"
// while it is on a CPU), which is exactly the state a signal has to find.
func waitBlockedInRead(tid int) error {
	path := fmt.Sprintf("/proc/self/task/%d/syscall", tid)
	want := fmt.Sprintf("%d 0x%x ", syscall.SYS_READ, reexecReadFd)
	deadline := time.Now().Add(reexecHandshakeTimeout)
	for {
		state, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if strings.HasPrefix(string(state), want) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("thread %d never blocked in the read (last state %q)", tid, state)
		}
		time.Sleep(time.Millisecond) // poll interval
	}
}

// clearSARestart re-installs the current handler of sig without SA_RESTART,
// so a syscall it interrupts fails with EINTR instead of being restarted. The
// Go runtime installs all its handlers with SA_RESTART and offers no way to
// change that, hence the raw rt_sigaction (kernelSigaction is the kernel's
// struct, see scenario_signals.go).
func clearSARestart(sig syscall.Signal) error {
	var act kernelSigaction
	if err := rtSigaction(sig, nil, &act); err != nil {
		return fmt.Errorf("rt_sigaction (get): %w", err)
	}
	if act.Handler <= sigIgn {
		return fmt.Errorf("signal %d has no handler (sa_handler=%d)", sig, act.Handler)
	}
	act.Flags &^= saRestart
	if err := rtSigaction(sig, &act, nil); err != nil {
		return fmt.Errorf("rt_sigaction (set): %w", err)
	}
	return nil
}

// rtSigaction is the raw rt_sigaction(2): act and old may each be nil.
func rtSigaction(sig syscall.Signal, act, old *kernelSigaction) error {
	_, _, errno := syscall.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig),
		uintptr(unsafe.Pointer(act)), uintptr(unsafe.Pointer(old)), sigSetBytes, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
