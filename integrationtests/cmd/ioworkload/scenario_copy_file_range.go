package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

// SYS_COPY_FILE_RANGE on x86_64 Linux.
const sysCopyFileRange = 326

// copyFileRangeBasic copies bytes from a source file to a destination file
// using copy_file_range(2) with flags=0 as required by the manpage.
func copyFileRangeBasic() error {
	dir, cleanup, err := makeTempDir("copy-file-range-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	srcPath := filepath.Join(dir, "copyrangesrc.txt")
	dstPath := filepath.Join(dir, "copyrangedst.txt")

	srcFd, err := syscall.Open(srcPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer syscall.Close(srcFd)

	dstFd, err := syscall.Open(dstPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer syscall.Close(dstFd)

	data := []byte("copy_file_range integration data")
	if _, err := syscall.Write(srcFd, data); err != nil {
		return fmt.Errorf("write source: %w", err)
	}
	if _, err := syscall.Seek(srcFd, 0, 0); err != nil {
		return fmt.Errorf("seek source: %w", err)
	}

	n, _, errno := syscall.Syscall6(uintptr(sysCopyFileRange), uintptr(srcFd), 0, uintptr(dstFd), 0, uintptr(len(data)), 0)
	if errno != 0 {
		return fmt.Errorf("copy_file_range: %w", errno)
	}
	if n == 0 {
		return fmt.Errorf("copy_file_range copied 0 bytes")
	}

	return nil
}

// copyFileRangeBadDstFd calls copy_file_range(2) with an invalid destination fd.
// The syscall should fail with EBADF, while still emitting the enter tracepoint.
func copyFileRangeBadDstFd() error {
	dir, cleanup, err := makeTempDir("copy-file-range-bad-dst")
	if err != nil {
		return err
	}
	defer cleanup()

	srcPath := filepath.Join(dir, "copyrangeebadfsrc.txt")
	srcFd, err := syscall.Open(srcPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer syscall.Close(srcFd)

	if _, err := syscall.Write(srcFd, []byte("copy_file_range ebadf data")); err != nil {
		return fmt.Errorf("write source: %w", err)
	}

	_, _, errno := syscall.Syscall6(uintptr(sysCopyFileRange), uintptr(srcFd), 0, uintptr(99999), 0, uintptr(16), 0)
	if errno != syscall.EBADF {
		return fmt.Errorf("expected EBADF from copy_file_range with invalid dst fd, got %v", errno)
	}

	return nil
}
