package main

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// reexecSampledReads is how many stopped reads the signal-reexec-many
	// scenario makes.
	reexecSampledReads = 32

	// reexecSampledFdBase is the first of the scenario's descriptors: read i
	// (from 0) goes through descriptor reexecSampledFdBase+i and returns i+1
	// bytes.
	reexecSampledFdBase = 300
)

// signalReexecMany makes reexecSampledReads blocking reads in a row, each
// interrupted by SIGSTOP/SIGCONT from an external stopper and re-executed by
// the kernel, as in the first phase of signal-reexec. The program sees
// reexecSampledReads reads, none of them failing.
//
// What sets the reads apart is in their values, not their timing: read i uses
// its own descriptor (all of them duplicates of one pipe's read end) and
// returns its own byte count, i+1. A trace row carries the descriptor from the
// call's enter and the return value from its exit, so a row is one of this
// scenario's reads exactly when the two belong together - which is what a
// test of the re-execution fold under 1-in-N sampling needs: with the
// re-executed call sampled out, a fold that took the thread's next read for
// the re-execution would pair descriptor i with the byte count of a later
// read (task 103).
//
// The handshakes are those of signal-reexec: the stop is sent only once /proc
// shows the reading thread blocked in this read, and the bytes are written
// only after the stopper saw the process stopped. The reads run on the main
// thread (tid == pid).
func signalReexecMany() error {
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	for i := 0; i < reexecSampledReads; i++ {
		if err := unix.Dup3(fds[0], reexecSampledFdBase+i, unix.O_CLOEXEC); err != nil {
			return fmt.Errorf("dup3 to %d: %w", reexecSampledFdBase+i, err)
		}
		defer syscall.Close(reexecSampledFdBase + i)
	}

	stopper, err := startStopper()
	if err != nil {
		return err
	}
	err = stoppedReads(stopper, fds[1], syscall.Gettid())
	return errors.Join(err, stopper.close())
}

// stoppedReads makes the scenario's reads one after the other; each must
// return its byte count without the program ever seeing EINTR.
func stoppedReads(stopper *reexecStopper, writeFd, tid int) error {
	for i := 0; i < reexecSampledReads; i++ {
		fd, n := reexecSampledFdBase+i, i+1
		interrupted := interruptAndFeed(writeFd, tid, fd, n, stopper.stopAndContinue)
		eintrs, readErr := blockingRead(fd, n)
		if err := errors.Join(readErr, <-interrupted); err != nil {
			return fmt.Errorf("stopped read %d: %w", i, err)
		}
		if eintrs != 0 {
			return fmt.Errorf("stopped read %d saw EINTR %d times, want none: no handler ran", i, eintrs)
		}
	}
	return nil
}
