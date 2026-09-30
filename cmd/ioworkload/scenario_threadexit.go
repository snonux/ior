package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// threadExitWait bounds how long the scenario waits for the kernel to reap
// the exited thread.
const threadExitWait = 5 * time.Second

// workerTidFileEnv names the file the thread-exit-tid-worker scenario writes
// its worker thread's TID to, so the harness can pass it to ior as -tid.
const workerTidFileEnv = "IOR_WORKLOAD_TID_FILE"

// scenarioPrestarts maps scenario names to hooks that run before the PID is
// announced (see main).
var scenarioPrestarts = map[string]func() error{
	"thread-exit-tid-worker": startTidWorker,
}

// tidWorker is the parked worker thread of thread-exit-tid-worker: start
// makes it run, done reports its I/O result and tid is its thread ID.
var tidWorker struct {
	tid   int
	start chan struct{}
	done  chan error
}

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

// startTidWorker parks a goroutine locked to its own non-main OS thread and
// publishes that thread's TID via $IOR_WORKLOAD_TID_FILE before ior starts,
// so ior can trace exactly that thread with -tid.
func startTidWorker() error {
	path := os.Getenv(workerTidFileEnv)
	if path == "" {
		return fmt.Errorf("%s is not set", workerTidFileEnv)
	}
	tidWorker.start = make(chan struct{})
	tidWorker.done = make(chan error, 1)
	tid := make(chan int)
	go func() {
		// Locked and never unlocked: when this goroutine returns, the Go
		// runtime terminates the thread (main.go init() keeps it off the
		// main thread).
		runtime.LockOSThread()
		tid <- unix.Gettid()
		<-tidWorker.start
		tidWorker.done <- pipeWriteOnce()
	}()
	tidWorker.tid = <-tid
	if tidWorker.tid == os.Getpid() {
		return errors.New("worker goroutine ran on the main thread; main.go init() must pin it")
	}
	return os.WriteFile(path, []byte(strconv.Itoa(tidWorker.tid)), 0o600)
}

// threadExitTidWorker drives the -tid group-dead bypass end to end: the traced
// worker thread does pipe I/O and exits (a record with group_dead clear, which
// must not evict), then the process exits from its other threads. The record
// that ends the thread group therefore comes from an *untraced* thread, and
// only the scoped bypass of the tid filter (TID_FILTER_TGID in
// internal/c/exec.c) lets it reach userspace, where ior counts it in its
// "group-dead exits" statistic.
func threadExitTidWorker() error {
	close(tidWorker.start)
	if err := <-tidWorker.done; err != nil {
		return err
	}
	// The worker's goroutine returns right after reporting; wait until the
	// kernel reaped its thread so the process exit below is not its own.
	return waitForThreadGone(tidWorker.tid)
}

// pipeWriteOnce creates a pipe, writes one byte and closes both ends.
func pipeWriteOnce() error {
	var pipefd [2]int
	if err := syscall.Pipe2(pipefd[:], syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	defer syscall.Close(pipefd[0])
	defer syscall.Close(pipefd[1])
	if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
		return fmt.Errorf("write pipe: %w", err)
	}
	return nil
}
