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
	"time"
	"unsafe"

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
	// threadCommRenamedName is the name the threads of threadCommRenamed give
	// themselves; it differs from the inherited "ioworkload".
	threadCommRenamedName = "iorworker"
	// threadCommRenameSettle is how long a renamed thread waits after its
	// warm-up pread before the measured ones, so the /proc read the warm-up
	// queued has landed. Generous: it only costs scenario wall time.
	threadCommRenameSettle = 150 * time.Millisecond
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

	fd, err := openThreadCommFile(dir, "data")
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	return runOnFreshThreads(threadCommThreads, func() error {
		return preadRepeatedly(fd, threadCommPreads)
	})
}

// threadCommRenamed is the thread-pool shape threadCommShortLived leaves out:
// each fresh thread renames itself (prctl(PR_SET_NAME), what pthread_setname_np
// does - tokio, Java, Chrome and Bun worker pools) before doing its work, so its
// name is no longer the one it inherited from this process and no tracepoint
// says so. It issues one pread on a warm-up file, sleeps threadCommRenameSettle,
// then threadCommPreads preads on the measured file.
//
// The task_newtask record can only name the thread "ioworkload"; the name the
// thread has by the time it works is learned from the one /proc read that the
// record's provisional seed allows (task fr2 review). The warm-up pread is what
// makes that read land: it is the first use of the tid that queues it, and rows
// on the warm-up file may still carry the inherited name (or, under -comm
// <renamed>, be dropped), so the test ignores them. Every row on the measured
// file must carry the renamed comm.
func threadCommRenamed() error {
	dir, cleanup, err := makeTempDir("thread-comm-renamed")
	if err != nil {
		return err
	}
	defer cleanup()

	warm, err := openThreadCommFile(dir, "warmup")
	if err != nil {
		return err
	}
	defer syscall.Close(warm)
	data, err := openThreadCommFile(dir, "measured")
	if err != nil {
		return err
	}
	defer syscall.Close(data)

	return runOnFreshThreads(threadCommThreads, func() error {
		if err := setThreadName(threadCommRenamedName); err != nil {
			return err
		}
		if err := preadRepeatedly(warm, 1); err != nil {
			return err
		}
		time.Sleep(threadCommRenameSettle)
		return preadRepeatedly(data, threadCommPreads)
	})
}

// setThreadName renames the calling thread with prctl(PR_SET_NAME), which the
// kernel truncates to 15 characters.
func setThreadName(name string) error {
	buf := append([]byte(name), 0)
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NAME, %q): %w", name, err)
	}
	return nil
}

// openThreadCommFile creates dir/name with a few bytes in it and returns a
// descriptor every thread of the scenario can pread.
func openThreadCommFile(dir, name string) (int, error) {
	fd, err := syscall.Open(filepath.Join(dir, name), syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", name, err)
	}
	if _, err := syscall.Write(fd, []byte("thread comm race")); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("write %s: %w", name, err)
	}
	return fd, nil
}

// preadRepeatedly issues n pread64 calls on fd.
func preadRepeatedly(fd, n int) error {
	buf := make([]byte, 8)
	for i := 0; i < n; i++ {
		if _, err := syscall.Pread(fd, buf, 0); err != nil {
			return fmt.Errorf("pread: %w", err)
		}
	}
	return nil
}

// runOnFreshThreads runs body on n distinct OS threads that were created after
// ior attached and returns the first error. Each body is one goroutine locked to
// its thread and never unlocked, so the thread is terminated when body returns
// (see threadCommShortLived for why threads that pre-date the scenario are
// skipped and retried).
func runOnFreshThreads(n int, body func() error) error {
	preexisting, err := currentThreadIDs()
	if err != nil {
		return err
	}
	var fresh atomic.Int32
	var firstErr atomic.Value
	for attempt := 0; int(fresh.Load()) < n; attempt++ {
		if attempt >= threadCommMaxBatches {
			return fmt.Errorf("only %d of %d goroutines ran on a fresh thread", fresh.Load(), n)
		}
		runFreshThreadBatch(n-int(fresh.Load()), preexisting, body, &fresh, &firstErr)
		if err, _ := firstErr.Load().(error); err != nil {
			return err
		}
	}
	return nil
}

// runFreshThreadBatch starts count goroutines, each locked to its OS thread and
// never unlocked, and waits for all of them. A goroutine whose thread predates
// the scenario (see threadCommShortLived) returns without running body; every
// other one runs it and counts itself in fresh when it succeeds.
func runFreshThreadBatch(count int, preexisting map[int]bool, body func() error,
	fresh *atomic.Int32, firstErr *atomic.Value) {
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			if preexisting[unix.Gettid()] {
				return
			}
			if err := body(); err != nil {
				firstErr.CompareAndSwap(nil, err)
				return
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
