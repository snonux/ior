package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// lateRenameThreads is how many fresh worker threads rename themselves
	// between the two phases of threadCommLateRename.
	lateRenameThreads = 12
	// lateRenameOps is how many calls each thread issues per phase.
	lateRenameOps = 4
	// lateRenameMainName is the name the main thread gives itself.
	lateRenameMainName = "main-renamed"
)

// lateRenameStyle is one of the ways a task's comm changes under it, all of
// which end in the kernel's __set_task_comm() and so in a task:task_rename
// record. The workers cycle through the styles so one run covers all of them.
type lateRenameStyle struct {
	name string
	// apply performs the rename for the calling worker. renamer is the channel
	// of the helper goroutine that writes /proc/self/task/<tid>/comm on a
	// worker's behalf (see startSiblingRenamer).
	apply func(name string, renamer chan<- siblingRename) error
}

var lateRenameStyles = []lateRenameStyle{
	// prctl(PR_SET_NAME) on itself: what a tokio or Java worker does.
	{name: "wk-prctl", apply: func(name string, _ chan<- siblingRename) error { return setThreadName(name) }},
	// A write to its own /proc/self/task/<tid>/comm: what
	// pthread_setname_np(pthread_self(), ...) does in glibc.
	{name: "wk-procself", apply: func(name string, _ chan<- siblingRename) error {
		return writeThreadComm(unix.Gettid(), name)
	}},
	// A write to its comm by *another* thread: pthread_setname_np(other, ...).
	// The renamed task is then not the task running the tracepoint handler.
	{name: "wk-sibling", apply: func(name string, renamer chan<- siblingRename) error {
		return renameBySibling(renamer, unix.Gettid(), name)
	}},
}

// threadCommLateRename is the rename shape threadCommRenamed leaves out: a task
// that is already known to ior (it issued traced syscalls under its old name)
// and then changes its name. Nothing but the task:task_rename record (task lr2)
// tells ior, so before it every later row kept the old name.
//
// Each task - the main thread and lateRenameThreads fresh workers - issues
// lateRenameOps pread64 calls (phase 1, old name), renames itself, and issues
// lateRenameOps pwrite64 calls (phase 2, new name). The phases differ by
// syscall so a test can tell them apart without a path. The workers rename in
// three different ways (lateRenameStyles); the rename is separated from phase 1
// by threadCommRenameSettle so the asynchronous /proc read ior queues for a new
// tid has certainly returned the old name before the rename, which is what
// lets a test hold phase 1 to the old name.
func threadCommLateRename() error {
	dir, cleanup, err := makeTempDir("thread-comm-late-rename")
	if err != nil {
		return err
	}
	defer cleanup()

	fd, err := openThreadCommFile(dir, "data")
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := renameMainBetweenPhases(fd); err != nil {
		return err
	}
	return renameWorkersBetweenPhases(fd)
}

// renameMainBetweenPhases runs the two phases on the main thread, the thread
// group leader (pid == tid), which exists before ior attaches.
func renameMainBetweenPhases(fd int) error {
	if err := preadRepeatedly(fd, lateRenameOps); err != nil {
		return err
	}
	time.Sleep(threadCommRenameSettle)
	if err := setThreadName(lateRenameMainName); err != nil {
		return err
	}
	return pwriteRepeatedly(fd, lateRenameOps)
}

// renameWorkersBetweenPhases runs the two phases on lateRenameThreads fresh
// threads, each renamed in the style its start order picks.
func renameWorkersBetweenPhases(fd int) error {
	renamer, stop := startSiblingRenamer()
	defer stop()
	var started atomic.Int32
	return runOnFreshThreads(lateRenameThreads, func() error {
		style := lateRenameStyles[int(started.Add(1)-1)%len(lateRenameStyles)]
		if err := preadRepeatedly(fd, lateRenameOps); err != nil {
			return err
		}
		time.Sleep(threadCommRenameSettle)
		if err := style.apply(style.name, renamer); err != nil {
			return err
		}
		return pwriteRepeatedly(fd, lateRenameOps)
	})
}

// pwriteRepeatedly issues n pwrite64 calls on fd.
func pwriteRepeatedly(fd, n int) error {
	for i := 0; i < n; i++ {
		if _, err := syscall.Pwrite(fd, []byte{'x'}, 0); err != nil {
			return fmt.Errorf("pwrite: %w", err)
		}
	}
	return nil
}

// writeThreadComm renames thread tid of this process by writing its procfs comm
// file, which is the interface pthread_setname_np uses.
func writeThreadComm(tid int, name string) error {
	path := fmt.Sprintf("/proc/self/task/%d/comm", tid)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := f.WriteString(name); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}

// siblingRename asks the renamer goroutine to rename thread tid and reports the
// outcome on done.
type siblingRename struct {
	tid  int
	name string
	done chan error
}

// startSiblingRenamer runs a helper goroutine that renames other threads of
// the process, and returns the channel to ask it on and the function that stops
// it. The helper is not one of the fresh worker threads: it is whichever
// thread the runtime schedules it on, which is the point - the renamed task and
// the task running the rename differ.
func startSiblingRenamer() (chan<- siblingRename, func()) {
	requests := make(chan siblingRename)
	go func() {
		for req := range requests {
			req.done <- writeThreadComm(req.tid, req.name)
		}
	}()
	return requests, func() { close(requests) }
}

// renameBySibling has the renamer goroutine rename the calling thread tid and
// waits until it has, so the caller's next syscall happens under the new name.
func renameBySibling(renamer chan<- siblingRename, tid int, name string) error {
	req := siblingRename{tid: tid, name: name, done: make(chan error, 1)}
	renamer <- req
	return <-req.done
}
