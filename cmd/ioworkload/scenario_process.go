package main

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const processExecEmitFor = 2 * time.Second

func processExecLifecycle() error {
	deadline := time.Now().Add(processExecEmitFor)
	for time.Now().Before(deadline) {
		if err := callExecveMissing(); err != nil {
			return err
		}
		if err := callExecveatMissing(); err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func callExecveMissing() error {
	filename, err := syscall.BytePtrFromString("/tmp/ior-missing-execve-only")
	if err != nil {
		return fmt.Errorf("execve filename: %w", err)
	}
	argv := []uintptr{uintptr(unsafe.Pointer(filename)), 0}
	envp := []uintptr{0}
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(filename)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envp[0])),
	)
	runtime.KeepAlive(filename)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(envp)
	if errno != syscall.ENOENT {
		return fmt.Errorf("execve errno=%v, want ENOENT", errno)
	}
	return nil
}

func callExecveatMissing() error {
	filename, err := syscall.BytePtrFromString("ior-missing-execveat-only")
	if err != nil {
		return fmt.Errorf("execveat filename: %w", err)
	}
	argv := []uintptr{uintptr(unsafe.Pointer(filename)), 0}
	envp := []uintptr{0}
	dirfdSigned := int64(unix.AT_FDCWD)
	dirfd := uintptr(dirfdSigned)
	_, _, errno := syscall.RawSyscall6(
		unix.SYS_EXECVEAT,
		dirfd,
		uintptr(unsafe.Pointer(filename)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envp[0])),
		0,
		0,
	)
	runtime.KeepAlive(filename)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(envp)
	if errno != syscall.ENOENT {
		return fmt.Errorf("execveat errno=%v, want ENOENT", errno)
	}
	return nil
}
