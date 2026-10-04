package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccompDeniedCalls is how often seccompDenied calls fchmod under the
// filter; the integration test expects that many exits without an enter.
const seccompDeniedCalls = 3

// seccompDenied makes calls a seccomp filter answers itself (task c23). A
// filter runs before the sys_enter tracepoint, and the call it skips still
// fires sys_exit, so ior sees an exit without an enter: no row, and a count
// in its "exits without an enter" statistic, in the share that looks like a
// filter's answer.
//
// One thread calls fchmod once for real (a row, and the thread is known to
// ior from then on), installs a filter that answers fchmod with EPERM
// (SECCOMP_RET_ERRNO), and calls it seccompDeniedCalls times more. A seccomp
// filter cannot be removed, so the thread is a throwaway: the goroutine
// returns locked to it, which makes the Go runtime end the thread, and no
// other thread of the workload carries the filter (no TSYNC).
//
// SECCOMP_RET_TRAP, whose exit carries the syscall number instead of an
// error, is not driven here: it raises SIGSYS, which the Go runtime treats
// as fatal when the kernel sends it.
func seccompDenied() error {
	dir, cleanup, err := makeTempDir("seccomp-denied")
	if err != nil {
		return err
	}
	defer cleanup()
	fd, err := syscall.Open(filepath.Join(dir, "denied.txt"), syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	done := make(chan error)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with us
		done <- fchmodUnderFilter(fd)
	}()
	return <-done
}

// fchmodUnderFilter runs on the throwaway thread: one fchmod that succeeds,
// the filter, and the denied ones, each of which must fail with EPERM.
func fchmodUnderFilter(fd int) error {
	if err := callFchmod(fd); err != nil {
		return err
	}
	if err := denyFchmodOnThisThread(); err != nil {
		return err
	}
	for i := range seccompDeniedCalls {
		if err := callFchmod(fd); !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("fchmod %d under the filter: %v, want EPERM", i, err)
		}
	}
	return nil
}

// denyFchmodOnThisThread installs, on the calling thread only, a seccomp
// filter that answers fchmod with EPERM and allows everything else. The
// filter reads the syscall number, the first word of seccomp_data.
func denyFchmodOnThisThread() error {
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: unix.SYS_FCHMOD},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(syscall.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
	}
	return nil
}
