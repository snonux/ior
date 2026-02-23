package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// dirBasic creates a directory via raw SYS_MKDIR, checks access, then removes it
// via raw SYS_RMDIR. We use raw syscalls because Go's syscall.Mkdir wraps mkdirat
// and syscall.Rmdir wraps unlinkat on amd64.
func dirBasic() error {
	dir, cleanup, err := makeTempDir("dir-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "subdir")
	pathBytes, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_MKDIR, uintptr(unsafe.Pointer(pathBytes)), 0o755, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("mkdir: %w", errno)
	}

	if err := syscall.Access(subDir, syscall.F_OK); err != nil {
		return fmt.Errorf("access: %w", err)
	}

	pathBytes2, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno = syscall.Syscall(syscall.SYS_RMDIR, uintptr(unsafe.Pointer(pathBytes2)), 0, 0)
	runtime.KeepAlive(pathBytes2)
	if errno != 0 {
		return fmt.Errorf("rmdir: %w", errno)
	}
	return nil
}

// dirMkdirat creates a directory via mkdirat(2) using Go's syscall.Mkdir
// which wraps mkdirat with AT_FDCWD on amd64.
func dirMkdirat() error {
	dir, cleanup, err := makeTempDir("dir-mkdirat")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "mkdirat-subdir")
	if err := syscall.Mkdir(subDir, 0o755); err != nil {
		return fmt.Errorf("mkdirat: %w", err)
	}
	return nil
}

// dirChdir creates a temp directory, then changes to it via chdir(2).
// Restores the original working directory afterward.
func dirChdir() error {
	origDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	dir, cleanup, err := makeTempDir("dir-chdir")
	if err != nil {
		return err
	}
	defer cleanup()
	defer syscall.Chdir(origDir)

	if err := syscall.Chdir(dir); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}
	return nil
}

// dirGetcwd changes into a temp directory and calls getcwd(2) directly.
func dirGetcwd() error {
	origDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	dir, cleanup, err := makeTempDir("dir-getcwd")
	if err != nil {
		return err
	}
	defer cleanup()
	defer syscall.Chdir(origDir)

	if err := syscall.Chdir(dir); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}

	buf := make([]byte, 4096)
	_, _, errno := syscall.Syscall(syscall.SYS_GETCWD, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("getcwd: %w", errno)
	}
	// Keep cwd unchanged long enough for ior to process enter/exit pairing.
	time.Sleep(300 * time.Millisecond)
	return nil
}

// dirGetdents opens a directory and reads its entries via getdents64(2).
func dirGetdents() error {
	dir, cleanup, err := makeTempDir("dir-getdents")
	if err != nil {
		return err
	}
	defer cleanup()

	// Create a file so getdents has something to return.
	filePath := filepath.Join(dir, "getdents-file.txt")
	fd, err := syscall.Open(filePath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	syscall.Close(fd)

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	buf := make([]byte, 4096)
	_, _, errno := syscall.Syscall(syscall.SYS_GETDENTS64, uintptr(dirFD), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("getdents64: %w", errno)
	}
	return nil
}

// dirMkdirEexist attempts to create a directory that already exists via raw
// SYS_MKDIR. The syscall fails with EEXIST, but ior captures the tracepoint
// on entry.
func dirMkdirEexist() error {
	dir, cleanup, err := makeTempDir("dir-mkdir-eexist")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "mkdir-eexist-subdir")
	pathBytes, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}

	// Create the directory first so the second attempt fails.
	_, _, errno := syscall.Syscall(syscall.SYS_MKDIR, uintptr(unsafe.Pointer(pathBytes)), 0o755, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("first mkdir: %w", errno)
	}

	// Second mkdir on the same path should fail with EEXIST.
	pathBytes2, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno = syscall.Syscall(syscall.SYS_MKDIR, uintptr(unsafe.Pointer(pathBytes2)), 0o755, 0)
	runtime.KeepAlive(pathBytes2)
	if errno == 0 {
		return fmt.Errorf("expected EEXIST, but mkdir succeeded")
	}
	return nil
}

// dirChdirEnoent attempts to change to a nonexistent directory via raw
// SYS_CHDIR. The syscall fails with ENOENT, but ior captures the tracepoint
// on entry.
func dirChdirEnoent() error {
	dir, cleanup, err := makeTempDir("dir-chdir-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	badPath := filepath.Join(dir, "chdir-enoent-missing")
	pathBytes, err := syscall.BytePtrFromString(badPath)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	// Retry a few times to reduce dropped-event flakiness under high load.
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
		runtime.KeepAlive(pathBytes)
		if errno == 0 {
			return fmt.Errorf("expected ENOENT, but chdir succeeded")
		}
	}
	return nil
}

// dirGetdentsEbadf calls getdents64(2) with an invalid file descriptor.
// The syscall fails with EBADF, but ior captures the tracepoint on entry.
func dirGetdentsEbadf() error {
	buf := make([]byte, 4096)
	// Retry a few times to reduce flakiness under high integration parallelism.
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_GETDENTS64, uintptr(9999), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		runtime.KeepAlive(buf)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but getdents64 succeeded")
		}
	}
	return nil
}
