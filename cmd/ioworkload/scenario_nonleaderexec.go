package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// execNonLeaderThread replaces the workload with /bin/true by calling execve
// from a non-main OS thread. The kernel's de_thread() then hands the calling
// thread the leader's tid (== pid), so the execve enters under the caller's
// tid and returns under the pid. ior must still pair the two (task 0p2): the
// sched_process_exec record carries the pre-exec tid and both the BPF enter
// state and the parked userspace enter are moved to the leader tid.
//
// main.go's init() pins the main goroutine to the main thread, so the locked
// goroutine below always runs on another thread. When $IOR_WORKLOAD_TID_FILE
// is set, the caller's tid is written there before the exec, so the test can
// assert the row reports exactly that thread. On success this function never
// returns: the process becomes true(1) and exits 0.
func execNonLeaderThread() error {
	target, err := exec.LookPath("true")
	if err != nil {
		return fmt.Errorf("look up true: %w", err)
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		result <- execFromThisThread(target)
	}()
	return <-result
}

// execWorker is the parked exec thread of exec-non-leader-thread-tid.
var execWorker parkedWorker

// startExecWorker parks the thread that will exec in exec-non-leader-thread-tid
// and publishes its TID before ior starts, so the harness can run ior with
// -tid <that thread> (task dp2). The plain scenario learns the tid only right
// before the exec, which is too late for a -tid argument.
func startExecWorker() error {
	target, err := exec.LookPath("true")
	if err != nil {
		return fmt.Errorf("look up true: %w", err)
	}
	execWorker, err = startParkedWorker(func() error { return execFromThisThread(target) })
	return err
}

// execNonLeaderThreadTid releases the parked exec thread. Like
// execNonLeaderThread it returns only if the exec failed: on success the
// process becomes true(1). ior traces only the exec'ing thread here, whose
// post-exec (leader) tid its filter rejects, so the execve's exit record never
// reaches it; the exec record flagged exit_untraced must complete the row.
func execNonLeaderThreadTid() error {
	close(execWorker.start)
	return <-execWorker.done
}

// execNonLeaderIntoOpen re-executes this workload from a non-main OS thread as
// the open-basic scenario (task os2). de_thread() kills the old leader, whose
// sched_process_exit record carries the leader's tid, and then hands that tid
// to the exec'ing thread: the new program runs under the leader tid (== pid)
// with the leader's start time. An ior traced with -tid <pid> must keep
// tracing it (its open of testfile.txt shows up) and end only when the new
// program exits. The new program inherits the environment, so its startup
// wait returns at once (the startup file already exists) and it holds on
// $IOR_WORKLOAD_HOLD_FILE like the original would have. On success this never
// returns.
func execNonLeaderIntoOpen() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable: %w", err)
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			result <- errors.New("exec goroutine ran on the main thread; main.go init() must pin it")
			return
		}
		err := syscall.Exec(self, []string{"ioworkload", "--scenario=open-basic"}, os.Environ())
		result <- fmt.Errorf("execve %s: %w", self, err)
	}()
	return <-result
}

// execFromThisThread publishes the calling thread's tid and execs target. It
// returns only on failure.
func execFromThisThread(target string) error {
	tid := unix.Gettid()
	if tid == os.Getpid() {
		return errors.New("exec goroutine ran on the main thread; main.go init() must pin it")
	}
	if path := os.Getenv(workerTidFileEnv); path != "" {
		if err := os.WriteFile(path, []byte(strconv.Itoa(tid)), 0o600); err != nil {
			return fmt.Errorf("write caller tid: %w", err)
		}
	}
	err := syscall.Exec(target, []string{"true"}, os.Environ())
	return fmt.Errorf("execve %s: %w", target, err)
}
