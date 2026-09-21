package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const processExecEmitFor = 2 * time.Second

func processKcmpFile() error { return processKcmp(0) }

func processKcmpVM() error { return processKcmp(1) }

// processKcmp compares this process with itself. Both variants deliberately
// pass an open descriptor as each index: KCMP_FILE must report that file,
// while KCMP_VM must ignore the same otherwise-valid descriptor numbers.
func processKcmp(comparison uintptr) error {
	dir, cleanup, err := makeTempDir("process-kcmp")
	if err != nil {
		return err
	}
	defer cleanup()
	fd, err := syscall.Open(filepath.Join(dir, "kcmp-target"), syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if err != nil {
		return fmt.Errorf("open kcmp target: %w", err)
	}
	defer syscall.Close(fd)
	pid := uintptr(os.Getpid())
	ret, _, errno := syscall.RawSyscall6(unix.SYS_KCMP, pid, pid, comparison, uintptr(fd), uintptr(fd), 0)
	// Checkpoint/restore support and ptrace policy vary by host. Even a
	// denied comparison still produces operands whose attribution is testable.
	if errno == syscall.EPERM || errno == syscall.ENOSYS {
		return nil
	}
	if errno != 0 {
		return fmt.Errorf("kcmp type %d: %w", comparison, errno)
	}
	if ret != 0 {
		return fmt.Errorf("kcmp type %d returned %d, want equality", comparison, ret)
	}
	return nil
}

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
