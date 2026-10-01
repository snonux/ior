package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// renameInOpenName is the name a sibling gives the worker while the worker
	// is blocked inside open(2).
	renameInOpenName = "fifo-renamed"
	// renameInOpenOps is how many pwrite64 calls the worker issues once its
	// open returns.
	renameInOpenOps = 4
)

// threadCommRenameInOpen is the ordering a rename can take that threadCommLateRename
// does not exercise: the rename lands *between* a syscall's enter and exit
// (task lr2 review). A fresh worker blocks in open(2) on the read end of a FIFO
// - the kernel's comm at that enter is "ioworkload" - and while it is blocked
// another thread renames it by writing /proc/self/task/<tid>/comm
// (pthread_setname_np(other, ...)). Only then does that thread open the write
// end, which lets the worker's open return. The worker then issues
// renameInOpenOps pwrite64 calls and closes the FIFO.
//
// The event stream is open-enter(comm=ioworkload), task_rename(renameInOpenName),
// open-exit. The open's payload comm is the stale one; applying it to ior's comm
// cache at the exit overwrote the rename, and every later row of the worker kept
// the old name. All of the worker's rows after the open must carry the new name.
func threadCommRenameInOpen() error {
	dir, cleanup, err := makeTempDir("thread-comm-rename-in-open")
	if err != nil {
		return err
	}
	defer cleanup()

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		return fmt.Errorf("mkfifo: %w", err)
	}
	fd, err := openThreadCommFile(dir, "data")
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	return runOnFreshThreads(1, func() error { return renamedWhileBlockedInOpen(fifo, fd) })
}

// renamedWhileBlockedInOpen is the worker body: it starts the sibling that
// renames it and then unblocks its open, blocks in open(2) on the FIFO's read
// end, and on return writes to the data file and closes the FIFO.
func renamedWhileBlockedInOpen(fifo string, dataFd int) error {
	sibling := startRenameThenUnblock(unix.Gettid(), fifo)
	fifoFd, err := syscall.Open(fifo, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open fifo read end: %w", err)
	}
	defer sibling.release()
	if err := <-sibling.opened; err != nil {
		syscall.Close(fifoFd)
		return err
	}
	if err := pwriteRepeatedly(dataFd, renameInOpenOps); err != nil {
		syscall.Close(fifoFd)
		return err
	}
	return syscall.Close(fifoFd)
}

// renameUnblocker is the helper goroutine of threadCommRenameInOpen. opened
// carries the outcome of its rename and of its open of the FIFO's write end;
// release lets it close that descriptor again.
type renameUnblocker struct {
	opened chan error
	done   chan struct{}
}

func (r *renameUnblocker) release() { close(r.done) }

// startRenameThenUnblock renames thread tid after threadCommRenameSettle, which
// gives the worker time to be blocked inside open(2) with ior having consumed
// its enter record, and only then opens the FIFO's write end. The rename
// therefore always happens-before the worker's open returns. The helper is not
// locked to a thread, and cannot run on the blocked worker, so the renamed task
// and the task doing the rename differ.
func startRenameThenUnblock(tid int, fifo string) *renameUnblocker {
	r := &renameUnblocker{opened: make(chan error, 1), done: make(chan struct{})}
	go func() {
		time.Sleep(threadCommRenameSettle)
		// A failed rename is reported, but the write end is opened anyway: the
		// worker is blocked in open(2) and would otherwise never return.
		renameErr := writeThreadComm(tid, renameInOpenName)
		wfd, err := syscall.Open(fifo, syscall.O_WRONLY, 0)
		if err != nil {
			r.opened <- fmt.Errorf("open fifo write end: %w", err)
			return
		}
		r.opened <- renameErr
		<-r.done
		syscall.Close(wfd)
	}()
	return r
}
