package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// fdTableMaxBatches bounds the retries needed to get a goroutine onto a
	// thread that pre-dates the scenario; each batch launches fdTableBatchSize
	// goroutines.
	fdTableMaxBatches = 50
	fdTableBatchSize  = 16
)

// threadCommFdTable is the end-to-end shape of task dr2. The main thread
// (TID == PID, whose comm ior seeds at startup, so -comm ioworkload keeps its
// rows) opens two files, a and b. A second thread that ior has never seen
// makes b's description also answer to a's descriptor number with
// dup3(b, a). The main thread then reads a's number: the row must report b's
// path, which only holds if ior applied the second thread's dup3 to the
// process's shared fd table.
//
// Why the second thread must pre-date the scenario: a thread created after ior
// attached is named by its task:task_newtask record before its first syscall
// (task fr2), so under -comm ioworkload it is a cached, matching thread and
// even the old enter-side gate let its syscalls through. A thread that already
// existed has no record, and ior seeds only the tracked pid's comm, so its
// first traced syscall meets a tid with no cached comm - the state the
// enter-side gate used to drop the enter of, which left the table unchanged
// and the main thread's read reporting a's path. The Go runtime keeps idle
// threads around from its startup, so the scenario looks for a goroutine that
// landed on one (see runOnPreexistingThread).
//
// Everything the assertion needs is traced by ior itself (openat, dup3, read):
// the read's path comes from the fd table, not from a lazy /proc lookup.
func threadCommFdTable() error {
	dir, cleanup, err := makeTempDir("thread-comm-fdtable")
	if err != nil {
		return err
	}
	defer cleanup()

	fdA, err := openThreadCommFile(dir, "fdtable-a.txt")
	if err != nil {
		return err
	}
	defer syscall.Close(fdA)
	fdB, err := openThreadCommFile(dir, "fdtable-b.txt")
	if err != nil {
		return err
	}
	defer syscall.Close(fdB)

	if err := runOnPreexistingThread(func() error {
		if err := unix.Dup3(fdB, fdA, 0); err != nil {
			return fmt.Errorf("dup3(%d, %d): %w", fdB, fdA, err)
		}
		return nil
	}); err != nil {
		return err
	}

	// The read must come after the dup3 has completed (runOnPreexistingThread
	// returns once body has), so its enter follows the dup3's exit record in
	// the ring buffer.
	buf := make([]byte, 8)
	if _, err := syscall.Pread(fdA, buf, 0); err != nil {
		return fmt.Errorf("pread(%s): %w", filepath.Join(dir, "fdtable-a.txt"), err)
	}
	return nil
}

// runOnPreexistingThread runs body once, on an OS thread other than the main
// one that already existed when the scenario started (ior is attached by then:
// main.go waits for the harness's startup signal), and returns body's error.
// It is the mirror image of runOnFreshThreads: a goroutine locked to a thread
// that was not in the snapshot declines and returns, which terminates that
// (fresh) thread; one on a pre-existing thread claims the single run slot.
// Goroutines are launched in batches until one has claimed it, and the
// scenario fails rather than run body somewhere else if none does, because the
// property under test would silently not be exercised.
func runOnPreexistingThread(body func() error) error {
	preexisting, err := currentThreadIDs()
	if err != nil {
		return err
	}
	var claimed atomic.Bool
	var ran atomic.Bool
	bodyErr := make(chan error, fdTableBatchSize*fdTableMaxBatches)
	for attempt := 0; attempt < fdTableMaxBatches && !ran.Load(); attempt++ {
		done := make(chan struct{}, fdTableBatchSize)
		for i := 0; i < fdTableBatchSize; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
				tid := unix.Gettid()
				if !preexisting[tid] || tid == unix.Getpid() || !claimed.CompareAndSwap(false, true) {
					return
				}
				bodyErr <- body()
				ran.Store(true)
			}()
		}
		for i := 0; i < fdTableBatchSize; i++ {
			<-done
		}
	}
	if !ran.Load() {
		return fmt.Errorf("no goroutine ran on a pre-existing thread after %d batches", fdTableMaxBatches)
	}
	return <-bodyErr
}
