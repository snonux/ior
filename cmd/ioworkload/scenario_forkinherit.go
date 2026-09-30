package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// forkInheritFds is the end-to-end shape of task gr2. The parent creates a pipe
// (ior traces pipe2 and names both ends "pipe:<flags>:<rfd>:<wfd>"), writes one
// byte, then fork()s; the child reads the byte from its inherited copy of the
// read end and exits. The child is a process ior has never seen: the fd table is
// keyed by tgid, so without the task_newtask inheritance its read row falls back
// to /proc/<child>/fd/<fd> - which spells the pipe "pipe:[N]", or, with the
// child already gone, cannot answer at all - instead of the parent's traced
// name. The child's read row must carry the same name as the parent's write row.
//
// The child runs raw syscalls only (read, exit_group) and touches no Go runtime
// state: after a raw fork the child is a single-threaded copy of a multi-threaded
// runtime, where any allocation, lock or scheduler call may deadlock on a mutex
// another (now nonexistent) thread held. The buffer lives on the stack, and the
// parent reaps the child with wait4 so the scenario does not leave a zombie.
//
// When $IOR_WORKLOAD_CHILD_PID_FILE is set the parent writes the child's pid
// there (after the fork, in the parent, where the runtime is intact). The
// system-wide ior of the integration test sees every process of the machine, so
// the test needs a way to tell this child's rows from those of any other
// ioworkload running at the same time; the pid is unique among live processes.
const childPidFileEnv = "IOR_WORKLOAD_CHILD_PID_FILE"

func forkInheritFds() error {
	var pipefd [2]int
	if err := syscall.Pipe2(pipefd[:], 0); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	defer syscall.Close(pipefd[0])
	defer syscall.Close(pipefd[1])
	if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
		return fmt.Errorf("write pipe: %w", err)
	}

	child, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("fork: %w", errno)
	}
	if child == 0 {
		forkChildReadAndExit(pipefd[0])
	}

	if err := publishChildPid(int(child)); err != nil {
		return err
	}

	var status syscall.WaitStatus
	if _, err := syscall.Wait4(int(child), &status, 0, nil); err != nil {
		return fmt.Errorf("wait4 child %d: %w", child, err)
	}
	if !status.Exited() || status.ExitStatus() != 0 {
		return fmt.Errorf("child %d did not read its inherited pipe end: %v", child, status)
	}
	return nil
}

// forkChildReadAndExit is the forked child's whole life: one read(2) on the
// inherited descriptor, then exit_group(0) on success or 1 on failure. It never
// returns, and deliberately calls nothing but raw syscalls (see forkInheritFds).
//
//go:nosplit
func forkChildReadAndExit(fd int) {
	var b [1]byte
	_, _, errno := syscall.RawSyscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), 1)
	code := uintptr(0)
	if errno != 0 {
		code = 1
	}
	// exit_group does not return; the loop only guarantees that a child that
	// somehow got past it can never fall back into the parent's code.
	for {
		_, _, _ = syscall.RawSyscall(syscall.SYS_EXIT_GROUP, code, 0, 0)
	}
}

// publishChildPid writes the forked child's pid to $IOR_WORKLOAD_CHILD_PID_FILE
// (a no-op when unset). The child is already running; whether the file appears
// before or after its read does not matter, the test reads it after the run.
func publishChildPid(pid int) error {
	path := os.Getenv(childPidFileEnv)
	if path == "" {
		return nil
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return fmt.Errorf("write child pid file: %w", err)
	}
	return nil
}
