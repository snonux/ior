package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// openBasic opens a file with O_RDWR|O_CREAT, then closes it.
func openBasic() error {
	dir, cleanup, err := makeTempDir("open-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "testfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	return syscall.Close(fd)
}

// openCreat creates a file via raw SYS_CREAT.
// Go's syscall.Creat wraps Open which delegates to openat on amd64,
// so we use the raw syscall to actually exercise the creat tracepoint.
func openCreat() error {
	dir, cleanup, err := makeTempDir("open-creat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "creatfile.txt")
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_CREAT, uintptr(unsafe.Pointer(pathBytes)), 0o644, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("creat: %w", errno)
	}
	return syscall.Close(int(fd))
}

// openEnoent attempts to open a nonexistent file path. The openat syscall
// returns ENOENT, but ior should still capture the enter_openat tracepoint
// because the filename is read on entry before the syscall executes.
func openEnoent() error {
	dir, cleanup, err := makeTempDir("open-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "nonexistent", "enoentfile.txt")
	_, err = syscall.Open(path, syscall.O_RDONLY, 0)
	if err == nil {
		return fmt.Errorf("expected ENOENT, but open succeeded")
	}
	return nil
}

// openRdonlyWrite opens a file O_RDONLY, then attempts to write to it.
// The write fails with EBADF, but ior should capture both the openat
// tracepoint and the write tracepoint.
func openRdonlyWrite() error {
	dir, cleanup, err := makeTempDir("open-rdonly-write")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "rdonlyfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	syscall.Close(fd)

	fd, err = syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open rdonly: %w", err)
	}
	defer syscall.Close(fd)

	_, err = syscall.Write(fd, []byte("should fail"))
	if err == nil {
		return fmt.Errorf("expected write to rdonly fd to fail")
	}
	return nil
}

// openPidFilter spawns a child process that performs file I/O. Since ior
// filters by the workload PID, the child's I/O should NOT appear in results.
// The parent also performs its own open so the test can verify positive and
// negative expectations simultaneously.
func openPidFilter() error {
	dir, cleanup, err := makeTempDir("open-pid-filter")
	if err != nil {
		return err
	}
	defer cleanup()

	// Parent opens a file (should be captured by ior).
	parentPath := filepath.Join(dir, "parentfile.txt")
	fd, err := syscall.Open(parentPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("parent open: %w", err)
	}
	syscall.Close(fd)

	// Spawn a child process that creates a file with a distinctive name.
	childPath := filepath.Join(dir, "childfile.txt")
	cmd := exec.Command("touch", childPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("child touch: %w", err)
	}
	return nil
}

// openByHandleAt creates a file, resolves its handle via name_to_handle_at,
// then opens it via open_by_handle_at. Requires root (CAP_DAC_READ_SEARCH).
// LockOSThread prevents goroutine migration between the two syscalls so that
// ior sees the same TID for both and can correlate the path.
func openByHandleAt() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dir, cleanup, err := makeTempDir("open-by-handle-at")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "handlefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	handle, mountFD, err := nameToHandleAt(dir, "handlefile.txt")
	if err != nil {
		return fmt.Errorf("name_to_handle_at: %w", err)
	}
	defer syscall.Close(mountFD)

	fd2, err := openByHandleAtSyscall(mountFD, handle, syscall.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open_by_handle_at: %w", err)
	}
	return syscall.Close(fd2)
}

// fileHandle matches the kernel's struct file_handle layout.
type fileHandle struct {
	Size uint32
	Type int32
	// Handle bytes follow immediately after.
}

const (
	sysNameToHandleAt = 303
	sysOpenByHandleAt = 304
)

// nameToHandleAt calls name_to_handle_at(2) and returns the file handle
// and the directory fd. The caller can pass this dirFD as the mount_fd
// argument to open_by_handle_at since any fd on the same filesystem works.
func nameToHandleAt(dirPath, name string) ([]byte, int, error) {
	dirFD, err := syscall.Open(dirPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open dir: %w", err)
	}

	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		syscall.Close(dirFD)
		return nil, 0, fmt.Errorf("name bytes: %w", err)
	}

	// Start with a buffer large enough for most handles.
	buf := make([]byte, unsafe.Sizeof(fileHandle{})+128)
	fh := (*fileHandle)(unsafe.Pointer(&buf[0]))
	fh.Size = uint32(len(buf) - int(unsafe.Sizeof(fileHandle{})))

	var mountID int32
	_, _, errno := syscall.Syscall6(
		sysNameToHandleAt,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(unsafe.Pointer(fh)),
		uintptr(unsafe.Pointer(&mountID)),
		0, 0,
	)
	if errno != 0 {
		syscall.Close(dirFD)
		return nil, 0, fmt.Errorf("syscall: %w", errno)
	}

	handleLen := int(unsafe.Sizeof(fileHandle{})) + int(fh.Size)
	handle := make([]byte, handleLen)
	copy(handle, buf[:handleLen])

	return handle, dirFD, nil
}

// openByHandleAtSyscall calls open_by_handle_at(2).
func openByHandleAtSyscall(mountFD int, handle []byte, flags int) (int, error) {
	fd, _, errno := syscall.Syscall(
		sysOpenByHandleAt,
		uintptr(mountFD),
		uintptr(unsafe.Pointer(&handle[0])),
		uintptr(flags),
	)
	if errno != 0 {
		return 0, fmt.Errorf("syscall: %w", errno)
	}
	return int(fd), nil
}

// openDurationGap performs two openat syscalls for the same path and flags,
// separated by a deliberate sleep. Integration tests use this to assert that
// durationToPrev captures inter-syscall gaps for the same event key.
func openDurationGap() error {
	dir, cleanup, err := makeTempDir("open-duration-gap")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "gap-shared.txt")

	fd1, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open first: %w", err)
	}
	if err := syscall.Close(fd1); err != nil {
		return fmt.Errorf("close first: %w", err)
	}

	time.Sleep(800 * time.Millisecond)

	fd2, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open second: %w", err)
	}
	return syscall.Close(fd2)
}
