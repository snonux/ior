package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// threadExitWait bounds how long the scenario waits for the kernel to reap
// the exited thread.
const threadExitWait = 5 * time.Second

// threadExitKeepsFd drives the sched_process_exit group_dead gate end to end:
// it creates a pipe, writes to it, lets one *other* thread of this process
// exit while the process lives on, and writes to the same descriptor again.
// ior must name both writes identically (its tracked pipe name), which only
// holds if the thread exit - a record with group_dead clear - left the
// process's fd-table entries alone. Evicting them would push the second
// write through the /proc/<pid>/fd fallback, which renames it (pipe:[inode])
// or, as observed, leaves it without any name.
func threadExitKeepsFd() error {
	var pipefd [2]int
	if err := syscall.Pipe2(pipefd[:], syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	defer syscall.Close(pipefd[0])
	defer syscall.Close(pipefd[1])

	if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
		return fmt.Errorf("write pipe before thread exit: %w", err)
	}
	if err := exitOneThread(); err != nil {
		return err
	}
	if _, err := syscall.Write(pipefd[1], []byte{2}); err != nil {
		return fmt.Errorf("write pipe after thread exit: %w", err)
	}
	return nil
}

// exitOneThread terminates one non-main OS thread of this process and waits
// until the kernel has reaped it. A goroutine that returns while locked to
// its OS thread makes the Go runtime exit that thread. main.go's init() pins
// the main goroutine to the main thread (tid == pid), so the throwaway
// goroutine always runs on another thread; the tid == pid check only guards
// that invariant, since returning locked on the main thread would wedge it
// rather than exit it.
func exitOneThread() error {
	tid := make(chan int)
	go func() {
		runtime.LockOSThread()
		self := unix.Gettid()
		if self == os.Getpid() {
			runtime.UnlockOSThread()
		}
		tid <- self
	}()
	exited := <-tid
	if exited == os.Getpid() {
		return errors.New("throwaway goroutine ran on the main thread; main.go init() must pin it")
	}
	return waitForThreadGone(exited)
}

// waitForThreadGone polls /proc/self/task until tid disappears. The kernel
// removes the entry in release_task(), after do_exit() has fired
// sched_process_exit, so the exit record is already in the ring buffer ahead
// of any syscall issued after this returns.
func waitForThreadGone(tid int) error {
	path := fmt.Sprintf("/proc/self/task/%d", tid)
	deadline := time.Now().Add(threadExitWait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("thread %d still present after %s", tid, threadExitWait)
}
