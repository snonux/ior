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
	// threadCommRenameSettle is how long a thread pauses between two phases of
	// a scenario. Since task lr2 a rename is reported by the task:task_rename
	// record, in ring-buffer order with the thread's syscalls, so the label of
	// a row no longer depends on how far ior's event loop trails the workload
	// (before it, the renamed name was learned from one asynchronous
	// /proc/<tid>/comm read that had to land before the measured rows). The
	// pause stays for threadCommLateRename, which holds the phase *before* a
	// rename to the old name: there it keeps that asynchronous read - ior
	// queues one for every new tid - from returning the new name. Generous: the
	// threads sleep concurrently, so it costs the scenario wall time once, not
	// per thread.
	threadCommRenameSettle = 500 * time.Millisecond
	// threadCommLinger is how long every thread, and with it the process, stays
	// alive after the last syscall of the scenario. ior resolves things it was
	// not told by the kernel - a path whose open it did not trace
	// (/proc/<pid>/fd/<fd>), the comm of a thread whose records were lost
	// (/proc/<tid>/comm) - lazily, when the event loop reaches the row. The
	// loop can trail the workload by a while on a busy machine, and a lookup
	// for a task that has already exited finds nothing, so the scenario must
	// not vanish the instant its work is done.
	// The harness has no way to know when ior has caught up, so this is a
	// generous bound (only lag beyond it can lose a lookup), not a handshake.
	// It protects lookups of tasks that would otherwise be gone; it does not
	// widen the rename tolerance, which threadCommRenameSettle alone bounds.
	threadCommLinger = time.Second
)

// threadCommShortLived makes threadCommThreads OS threads that ior has
// certainly seen being created each issue threadCommPreads pread64 calls on one
// shared file within microseconds of starting. Each such thread is a task ior
// has never traced before: its comm can only be known in time from the
// task:task_newtask record (task fr2), because an asynchronous /proc lookup
// lands after the thread's first rows were already emitted (and, for a thread
// that exits at once, finds no process at all). The threads inherit this
// process's comm ("ioworkload"). They idle for threadCommLinger afterwards
// rather than exit, so the outcome does not hinge on how far ior's event loop
// trails the workload: the rows' comm must come from the record, and a row's
// lazily resolved path must not decide whether the test passes.
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
// name is no longer the one it inherited from this process. It issues one
// pwrite64 (the warm-up), sleeps threadCommRenameSettle, then threadCommPreads
// pread64 calls (the measured ones).
//
// The task_newtask record can only name the thread "ioworkload"; the rename is
// reported by the task:task_rename record (task lr2), which reaches ior in
// ring-buffer order right after it, so every row of the thread - the warm-up
// included - carries the new name. The two phases are kept apart by syscall
// rather than by file so that tests can tell them apart without a path: a path
// ior did not see opened is resolved lazily from /proc/<pid>/fd, which only
// works while the process is alive, so every thread stays alive for
// threadCommLinger after its work (see runOnFreshThreads). Before task lr2 the
// new name was learned from one asynchronous /proc read queued by the warm-up
// row, which is why the warm-up row could carry the inherited name and the
// measured rows depended on the pause.
func threadCommRenamed() error {
	dir, cleanup, err := makeTempDir("thread-comm-renamed")
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
		if err := setThreadName(threadCommRenamedName); err != nil {
			return err
		}
		if _, err := syscall.Pwrite(fd, []byte{'x'}, 0); err != nil {
			return fmt.Errorf("pwrite: %w", err)
		}
		time.Sleep(threadCommRenameSettle)
		return preadRepeatedly(fd, threadCommPreads)
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
// its thread and never unlocked, so the thread is terminated when the goroutine
// returns (see threadCommShortLived for why threads that pre-date the scenario
// are skipped and retried).
//
// A thread that has run its body does not exit at once: it parks until every
// thread has finished and threadCommLinger has passed, so ior can still resolve
// the comm and fd names of tasks it has not yet looked up (see
// threadCommLinger). The threads therefore all die together at the end, and the
// process exits right after.
func runOnFreshThreads(n int, body func() error) error {
	preexisting, err := currentThreadIDs()
	if err != nil {
		return err
	}
	var fresh atomic.Int32
	var firstErr atomic.Value
	release := make(chan struct{})
	var exited sync.WaitGroup
	defer func() {
		time.Sleep(threadCommLinger)
		close(release)
		exited.Wait()
	}()
	for attempt := 0; int(fresh.Load()) < n; attempt++ {
		if attempt >= threadCommMaxBatches {
			return fmt.Errorf("only %d of %d goroutines ran on a fresh thread", fresh.Load(), n)
		}
		runFreshThreadBatch(n-int(fresh.Load()), preexisting, body, &fresh, &firstErr, release, &exited)
		if err, _ := firstErr.Load().(error); err != nil {
			return err
		}
	}
	return nil
}

// runFreshThreadBatch starts count goroutines, each locked to its OS thread and
// never unlocked, and waits until each has either declined (its thread predates
// the scenario - see threadCommShortLived - so it returns without running body)
// or finished body. A goroutine that ran body counts itself in fresh when it
// succeeds and then parks on release, registered in exited, so its thread stays
// alive after the batch returns.
func runFreshThreadBatch(count int, preexisting map[int]bool, body func() error,
	fresh *atomic.Int32, firstErr *atomic.Value, release <-chan struct{}, exited *sync.WaitGroup) {
	var settled sync.WaitGroup
	for i := 0; i < count; i++ {
		settled.Add(1)
		exited.Add(1)
		go func() {
			defer exited.Done()
			runtime.LockOSThread()
			if preexisting[unix.Gettid()] {
				settled.Done()
				return
			}
			if err := body(); err != nil {
				firstErr.CompareAndSwap(nil, err)
			} else {
				fresh.Add(1)
			}
			settled.Done()
			<-release
		}()
	}
	settled.Wait()
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
