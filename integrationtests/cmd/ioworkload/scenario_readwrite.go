package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// readwriteBasic opens a file, writes data, seeks to start, reads it back.
func readwriteBasic() error {
	dir, cleanup, err := makeTempDir("readwrite-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "rwfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("hello from ioworkload")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	buf := make([]byte, len(data))
	if _, err := syscall.Read(fd, buf); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	return nil
}

// readwritePread opens a file, writes data, then reads it back via pread64.
func readwritePread() error {
	dir, cleanup, err := makeTempDir("readwrite-pread")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "preadfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("pread test data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, len(data))
	if _, err := syscall.Pread(fd, buf, 0); err != nil {
		return fmt.Errorf("pread: %w", err)
	}
	return nil
}

// readwritePwrite opens a file and writes data via pwrite64.
func readwritePwrite() error {
	dir, cleanup, err := makeTempDir("readwrite-pwrite")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "pwritefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Pwrite(fd, []byte("pwrite test data"), 0); err != nil {
		return fmt.Errorf("pwrite: %w", err)
	}
	return nil
}

// readwriteReadv opens a file, writes data, then reads it back via readv.
func readwriteReadv() error {
	dir, cleanup, err := makeTempDir("readwrite-readv")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "readvfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("readv test data here")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	buf1 := make([]byte, 5)
	buf2 := make([]byte, 15)
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	_, _, errno := syscall.Syscall(syscall.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)))
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("readv: %w", errno)
	}
	return nil
}

// readwriteWritev opens a file and writes data via writev.
func readwriteWritev() error {
	dir, cleanup, err := makeTempDir("readwrite-writev")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "writevfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	buf1 := []byte("writev ")
	buf2 := []byte("test data")
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	_, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)))
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("writev: %w", errno)
	}
	return nil
}

// readwriteWronlyRead opens a file O_WRONLY, then attempts to read from it.
// The read fails with EBADF, but ior should capture the enter_read tracepoint
// because arguments are read on syscall entry before the kernel returns an error.
func readwriteWronlyRead() error {
	dir, cleanup, err := makeTempDir("readwrite-wronly-read")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "wronlyfile.txt")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	buf := make([]byte, 16)
	_, err = syscall.Read(fd, buf)
	if err == nil {
		return fmt.Errorf("expected read from wronly fd to fail")
	}
	return nil
}

// readwriteRdonlyWrite opens a file O_RDONLY, then attempts to write to it.
// The write fails with EBADF, but ior should capture the enter_write tracepoint
// because arguments are read on syscall entry before the kernel returns an error.
func readwriteRdonlyWrite() error {
	dir, cleanup, err := makeTempDir("readwrite-rdonly-write")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "rdonlywritefile.txt")
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

// readwritePreadInvalid calls pread64 with a negative offset (-1).
// The syscall fails with EINVAL, but ior should capture the enter_pread64
// tracepoint because arguments are read on syscall entry.
func readwritePreadInvalid() error {
	dir, cleanup, err := makeTempDir("readwrite-pread-invalid")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "preadinvalid.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("some data")); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 16)
	_, err = syscall.Pread(fd, buf, -1)
	if err == nil {
		return fmt.Errorf("expected pread with negative offset to fail")
	}
	return nil
}

// readwritePwriteInvalid calls pwrite64 with a negative offset (-1).
// The syscall fails with EINVAL, but ior should capture the enter_pwrite64
// tracepoint because arguments are read on syscall entry.
func readwritePwriteInvalid() error {
	dir, cleanup, err := makeTempDir("readwrite-pwrite-invalid")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "pwriteinvalid.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	_, err = syscall.Pwrite(fd, []byte("should fail"), -1)
	if err == nil {
		return fmt.Errorf("expected pwrite with negative offset to fail")
	}
	return nil
}
