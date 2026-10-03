package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
)

// closeUntrackedBlockedBytes is how much close-untracked's last write puts
// into its FIFO: four times what a pipe holds by default (64 KiB), so the
// write blocks until the FIFO is drained.
const closeUntrackedBlockedBytes = 256 * 1024

// openUntrackedFifo creates a FIFO in dir and opens it twice before ior
// attaches, for writing and for draining. O_RDWR does not wait for the other
// end (Linux), and both descriptors are numbered after the regular files.
func openUntrackedFifo(dir string) error {
	path := filepath.Join(dir, "closeuntracked-fifo")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		return fmt.Errorf("mkfifo: %w", err)
	}
	fifoFd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open fifo: %w", err)
	}
	drainFd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open fifo for draining: %w", err)
	}
	closeUntrackedState.fifoFd, closeUntrackedState.drainFd = fifoFd, drainFd
	return nil
}

// closeUnderBlockedWrite is the deterministic form of close-untracked's race
// (task a23): a write of closeUntrackedBlockedBytes to the FIFO descriptor fd
// blocks in a thread of its own; once /proc shows it asleep in the write, fd
// is closed and a pipe takes the number (closeAndReuse), and only then is the
// FIFO drained through drain, which lets the write return. Its exit record -
// the moment ior resolves the row - therefore always comes after the pipe2
// exit that put the pipe on the number: ior's fd table and /proc/<pid>/fd both
// show the pipe, whatever the load. The write keeps its own reference to the
// FIFO, so the close does not disturb it.
func closeUnderBlockedWrite(fd, drain int) error {
	tids := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tids <- syscall.Gettid()
		n, err := syscall.Write(fd, make([]byte, closeUntrackedBlockedBytes))
		if err == nil && n != closeUntrackedBlockedBytes {
			err = fmt.Errorf("short write %d", n)
		}
		done <- err
	}()
	tid := <-tids
	if err := waitBlockedIn(tid, fmt.Sprintf("%d 0x%x ", syscall.SYS_WRITE, fd), "the fifo write"); err != nil {
		return err
	}
	if err := closeAndReuse(fd, false); err != nil {
		return err
	}
	if err := drainFifo(drain, closeUntrackedBlockedBytes); err != nil {
		return err
	}
	if err := <-done; err != nil {
		return fmt.Errorf("blocked fifo write: %w", err)
	}
	return nil
}

// drainFifo reads n bytes from fd.
func drainFifo(fd, n int) error {
	buf := make([]byte, 64*1024)
	for n > 0 {
		got, err := syscall.Read(fd, buf[:min(n, len(buf))])
		if err != nil {
			return fmt.Errorf("drain fifo: %w", err)
		}
		n -= got
	}
	return nil
}
