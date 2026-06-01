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

// readwritePreadv opens a file, writes data, then reads it back via preadv
// (positional vectored read). preadv returns the number of bytes read and is
// READ_CLASSIFIED, so the scenario reads a known payload to validate
// end-to-end byte attribution for the positional vectored read variant.
func readwritePreadv() error {
	dir, cleanup, err := makeTempDir("readwrite-preadv")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "preadvfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("preadv test data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf1 := make([]byte, 6)
	buf2 := make([]byte, 10)
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	// preadv(fd, iov, iovcnt, offset) reads at the given offset (0) without
	// changing the file position.
	_, _, errno := syscall.Syscall6(syscall.SYS_PREADV, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)), 0, 0, 0)
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("preadv: %w", errno)
	}
	return nil
}

// readwritePreadv2 opens a file, writes data, then reads it back via preadv2
// (positional vectored read with flags). Like preadv it returns the bytes read
// and is READ_CLASSIFIED; the scenario reads a known payload to validate
// end-to-end byte attribution.
func readwritePreadv2() error {
	dir, cleanup, err := makeTempDir("readwrite-preadv2")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "preadv2file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("preadv2 test data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf1 := make([]byte, 7)
	buf2 := make([]byte, 10)
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	nr, err := preadv2SyscallNr(runtime.GOARCH)
	if err != nil {
		return err
	}
	// preadv2(fd, iov, iovcnt, pos_l, pos_h, flags): offset 0, no flags.
	_, _, errno := syscall.Syscall6(nr, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)), 0, 0, 0)
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("preadv2: %w", errno)
	}
	return nil
}

// preadv2SyscallNr returns the preadv2(2) syscall number for the given GOARCH.
// Go's syscall package lacks a SYS_PREADV2 constant, so the architecture
// numbers are provided explicitly (matching securitySyscallNumbers' pattern).
func preadv2SyscallNr(arch string) (uintptr, error) {
	switch arch {
	case "amd64":
		return 327, nil
	case "arm64":
		return 286, nil
	default:
		return 0, fmt.Errorf("preadv2 syscall number not defined for GOARCH=%s", arch)
	}
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

// readwritePwritev opens a file and writes data via pwritev (positional
// vectored write). pwritev returns the number of bytes written and is
// WRITE_CLASSIFIED, so the scenario writes a known iovec total to validate
// end-to-end byte attribution for the positional vectored write variant.
func readwritePwritev() error {
	dir, cleanup, err := makeTempDir("readwrite-pwritev")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "pwritevfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	buf1 := []byte("pwritev ")
	buf2 := []byte("test data")
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	// pwritev(fd, iov, iovcnt, offset) writes at the given offset (0) without
	// changing the file position.
	_, _, errno := syscall.Syscall6(syscall.SYS_PWRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)), 0, 0, 0)
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("pwritev: %w", errno)
	}
	return nil
}

// readwritePwritev2 opens a file and writes data via pwritev2 (positional
// vectored write with flags). Like pwritev it returns the bytes written and is
// WRITE_CLASSIFIED; the scenario writes a known iovec total to validate
// end-to-end byte attribution.
func readwritePwritev2() error {
	dir, cleanup, err := makeTempDir("readwrite-pwritev2")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "pwritev2file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	buf1 := []byte("pwritev2 ")
	buf2 := []byte("test data")
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	nr, err := pwritev2SyscallNr(runtime.GOARCH)
	if err != nil {
		return err
	}
	// pwritev2(fd, iov, iovcnt, pos_l, pos_h, flags): offset 0, no flags.
	_, _, errno := syscall.Syscall6(nr, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)), 0, 0, 0)
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("pwritev2: %w", errno)
	}
	return nil
}

// pwritev2SyscallNr returns the pwritev2(2) syscall number for the given GOARCH.
// Go's syscall package lacks a SYS_PWRITEV2 constant, so the architecture
// numbers are provided explicitly (mirroring preadv2SyscallNr).
func pwritev2SyscallNr(arch string) (uintptr, error) {
	switch arch {
	case "amd64":
		return 328, nil
	case "arm64":
		return 287, nil
	default:
		return 0, fmt.Errorf("pwritev2 syscall number not defined for GOARCH=%s", arch)
	}
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

// readwriteReadahead opens a file, writes data, then calls readahead(2) on it.
// readahead(fd, offset, count) initiates non-blocking readahead so subsequent
// reads are served from the page cache. Despite its ssize_t prototype it returns
// 0 on success / -1 on error (it does NOT return a byte count and transfers no
// bytes to userspace), so ior classifies it KindFd / UNCLASSIFIED. The scenario
// exercises the enter fd_event (fd at args[0]) and the exit ret_event end-to-end.
func readwriteReadahead() error {
	dir, cleanup, err := makeTempDir("readwrite-readahead")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "readaheadfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("readahead test data")); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// readahead(fd, offset=0, count=4096): prime the page cache for the file.
	_, _, errno := syscall.Syscall(syscall.SYS_READAHEAD, uintptr(fd), 0, 4096)
	if errno != 0 {
		return fmt.Errorf("readahead: %w", errno)
	}
	return nil
}

// readwriteReadaheadEbadf calls readahead(2) on an invalid fd.
// The syscall fails with EBADF, but ior captures the enter_readahead tracepoint
// because arguments are read on syscall entry before the kernel returns an error.
func readwriteReadaheadEbadf() error {
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_READAHEAD, 99999, 0, 4096)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but readahead succeeded")
		}
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
