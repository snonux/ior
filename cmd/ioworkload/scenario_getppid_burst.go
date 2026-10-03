package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// getppidBurstCalls is how many getppid calls the burst child makes. Each one
// costs ior two ring-buffer records (enter and exit), and the test that
// counts them (integrationtests, task f23) mirrors the figure.
const getppidBurstCalls = 1_500_000

// burstChild is the forked child of getppid-burst: its pid, and the write end
// of the pipe whose first byte starts its calls.
var burstChild struct {
	pid   int
	start int
}

// startGetppidBurstChild is the prestart hook of getppid-burst: it forks the
// child that will make the calls, parked on a pipe read, and publishes its
// pid in $IOR_WORKLOAD_CHILD_PID_FILE before the workload announces its own,
// so the harness can trace the child with -pid.
//
// Why a forked child and not this process: the test counts every record ior
// accounts for, and the count must be known exactly. A raw fork child is one
// thread and stays one, so the records that pass a -pid filter on it are two
// per getppid call and its one exit record, nothing else. This process
// cannot offer that: the Go runtime starts threads when it likes, also while
// the loop runs (seen 1 ms before the exit), and every thread adds an exit
// record and, when it was created under the trace, a task_newtask record.
// The test first counted the threads from /proc/<pid>/task and was wrong by
// a record or two about once in 13 runs.
//
// The child is forked here, before ior starts, so that its fork leaves no
// record either, and it reads its pipe before ior attaches.
func startGetppidBurstChild() error {
	path := os.Getenv(childPidFileEnv)
	if path == "" {
		return fmt.Errorf("%s is not set", childPidFileEnv)
	}
	var pipefd [2]int
	if err := syscall.Pipe2(pipefd[:], 0); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	child, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("fork: %w", errno)
	}
	if child == 0 {
		getppidBurstChild(pipefd[0], pipefd[1])
	}
	// The child holds its own copy of the read end.
	_ = syscall.Close(pipefd[0])
	burstChild.pid, burstChild.start = int(child), pipefd[1]
	return publishChildPid(burstChild.pid)
}

// getppidBurstChild is the forked child's whole life: it waits for the start
// byte, calls getppid in a tight loop and exits right behind the last call.
// The loop outruns ior's event loop, which is the point: a trace that stops
// on the target's exit can then stop with a backlog in rawCh and in the
// kernel ring buffer (when ior's liveness check sees the exit before the loop
// has caught up), and its end-of-run figures must still account for every
// record. getppid is used because it does no I/O and is the one syscall the
// test traces: the wait on the pipe and the exit_group leave no syscall
// record.
//
// It never returns and calls nothing but raw syscalls, like
// forkChildReadAndExit and for the same reason: the child is a
// single-threaded copy of a multi-threaded runtime. It closes its copy of
// the pipe's write end first, so that a parent that dies before the start
// ends the read with an end of file; the child then exits with 1 without a
// call.
//
//go:nosplit
func getppidBurstChild(start, parentEnd int) {
	var b [1]byte
	_, _, _ = syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(parentEnd), 0, 0)
	n, _, errno := syscall.RawSyscall(syscall.SYS_READ, uintptr(start), uintptr(unsafe.Pointer(&b[0])), 1)
	code := uintptr(0)
	if errno != 0 || n != 1 {
		code = 1
	} else {
		for range getppidBurstCalls {
			_, _, _ = syscall.RawSyscall(syscall.SYS_GETPPID, 0, 0, 0)
		}
	}
	// exit_group does not return; the loop only guarantees that a child that
	// somehow got past it can never fall back into the parent's code.
	for {
		_, _, _ = syscall.RawSyscall(syscall.SYS_EXIT_GROUP, code, 0, 0)
	}
}

// getppidBurst starts the child's calls and reaps it, so the scenario ends
// when the calls are done and leaves no zombie.
func getppidBurst() error {
	if burstChild.pid == 0 {
		return errors.New("the burst child was not started (prestart hook)")
	}
	if _, err := syscall.Write(burstChild.start, []byte{1}); err != nil {
		return fmt.Errorf("start the burst child: %w", err)
	}
	_ = syscall.Close(burstChild.start)
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(burstChild.pid, &status, 0, nil); err != nil {
		return fmt.Errorf("wait4 child %d: %w", burstChild.pid, err)
	}
	if !status.Exited() || status.ExitStatus() != 0 {
		return fmt.Errorf("burst child %d did not make its calls: %v", burstChild.pid, status)
	}
	return nil
}
