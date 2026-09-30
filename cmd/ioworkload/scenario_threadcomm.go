package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// threadCommThreads is how many short-lived OS threads the scenario spawns.
	threadCommThreads = 40
	// threadCommPreads is how many preads each of them issues before exiting.
	threadCommPreads = 4
	// threadCommMaxBatches bounds the retries needed when goroutines land on
	// pre-existing threads; each batch launches only the missing goroutines.
	threadCommMaxBatches = 50
)

// threadCommShortLived makes threadCommThreads OS threads that ior has
// certainly seen being created each issue threadCommPreads pread64 calls on one
// shared file and exit at once. Each such thread is a task ior has never traced
// before: its comm can only be known from the task:task_newtask record (task
// fr2), because an asynchronous /proc lookup either loses the race against a
// thread that lives a few microseconds or lands after its first rows were
// already emitted. The threads inherit this process's comm ("ioworkload").
//
// A goroutine that returns while locked to its OS thread makes the Go runtime
// terminate that thread, so each goroutine is one short-lived kernel task. The
// catch is that LockOSThread pins the goroutine to whichever thread it happens
// to run on, and that is often an idle runtime thread created long before ior
// attached - a thread no newtask record exists for, which would fail the test
// for a reason unrelated to the fix. The scenario therefore snapshots the
// threads that exist when it starts (ior is attached by then: main.go waits for
// the harness's startup signal) and lets a goroutine that landed on one of them
// exit without a syscall, launching more goroutines until enough fresh threads
// have done the work. main.go's init() keeps the main goroutine on the main
// thread, so none of them can be the leader.
func threadCommShortLived() error {
	dir, cleanup, err := makeTempDir("thread-comm")
	if err != nil {
		return err
	}
	defer cleanup()

	fd, err := syscall.Open(filepath.Join(dir, "data"), syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, []byte("thread comm race")); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	preexisting, err := currentThreadIDs()
	if err != nil {
		return err
	}
	var fresh atomic.Int32
	var firstErr atomic.Value
	for attempt := 0; fresh.Load() < threadCommThreads; attempt++ {
		if attempt >= threadCommMaxBatches {
			return fmt.Errorf("only %d of %d goroutines ran on a fresh thread", fresh.Load(), threadCommThreads)
		}
		runThreadCommBatch(fd, int(threadCommThreads-fresh.Load()), preexisting, &fresh, &firstErr)
		if err, _ := firstErr.Load().(error); err != nil {
			return err
		}
	}
	return nil
}

// runThreadCommBatch starts n goroutines, each locked to its OS thread and
// never unlocked, and waits for all of them. A goroutine whose thread predates
// the scenario (see threadCommShortLived) returns without a syscall; every
// other one reads fd threadCommPreads times and counts itself in fresh.
func runThreadCommBatch(fd, n int, preexisting map[int]bool, fresh *atomic.Int32, firstErr *atomic.Value) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			if preexisting[unix.Gettid()] {
				return
			}
			buf := make([]byte, 8)
			for j := 0; j < threadCommPreads; j++ {
				if _, err := syscall.Pread(fd, buf, 0); err != nil {
					firstErr.CompareAndSwap(nil, fmt.Errorf("pread: %w", err))
					return
				}
			}
			fresh.Add(1)
		}()
	}
	wg.Wait()
}

// currentThreadIDs lists the thread ids of this process from /proc/self/task.
func currentThreadIDs() (map[int]bool, error) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, fmt.Errorf("list /proc/self/task: %w", err)
	}
	ids := make(map[int]bool, len(entries))
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("parse thread id %q: %w", entry.Name(), err)
		}
		ids[tid] = true
	}
	return ids, nil
}
