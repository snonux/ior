package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// noreturnSignals is how many SIGUSR1 handler returns (rt_sigreturn calls)
// the noreturn-syscalls scenario makes at least.
const noreturnSignals = 3

// noreturnSignalWait bounds the wait for one signal to reach the Go handler.
const noreturnSignalWait = 5 * time.Second

// noreturnSyscalls makes the three syscalls that never return to their
// caller, so ior must report them as rows at enter (task pr2):
//
//   - rt_sigreturn: SIGUSR1 goes through os/signal.Notify, so the Go runtime's
//     own handler runs and returns through the signal trampoline, which calls
//     rt_sigreturn. Each tgkill is waited for on the channel, so at least
//     noreturnSignals handler returns happen (the runtime's SIGURG preemption
//     can add more).
//   - exit: exitOneThread lets a goroutine locked to a non-main OS thread
//     return, and the Go runtime ends that thread with exit(2).
//   - exit_group: returning from main ends the process with exit_group(2),
//     from the main thread (main.go init() pins the main goroutine there).
//
// The tgkill calls double as the negative control: an ordinary returning
// syscall in the same run must still pair enter with exit.
func noreturnSyscalls() error {
	sigs := make(chan os.Signal, noreturnSignals)
	signal.Notify(sigs, syscall.SIGUSR1)
	defer signal.Stop(sigs)

	for i := 0; i < noreturnSignals; i++ {
		if err := unix.Tgkill(os.Getpid(), unix.Gettid(), syscall.SIGUSR1); err != nil {
			return fmt.Errorf("tgkill: %w", err)
		}
		select {
		case <-sigs:
		case <-time.After(noreturnSignalWait):
			return fmt.Errorf("SIGUSR1 %d not delivered within %s", i+1, noreturnSignalWait)
		}
	}
	return exitOneThread()
}
