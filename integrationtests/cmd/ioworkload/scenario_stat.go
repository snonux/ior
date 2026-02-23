package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	sysStatx       = 332
	rOK            = 0x4    // R_OK
	statxBasicMask = 0x07ff // STATX_BASIC_STATS
	atFDCwd        = -100   // AT_FDCWD
)

// statBasic creates a file and stats it via raw SYS_STAT (newstat).
// We use the raw syscall because Go's syscall.Stat wraps newfstatat on amd64.
func statBasic() error {
	dir, cleanup, err := makeTempDir("stat-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "statfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	var stat syscall.Stat_t
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_STAT, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(&stat)), 0)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&stat)
	if errno != 0 {
		return fmt.Errorf("stat: %w", errno)
	}
	return nil
}

// statFstat creates a file and stats it via raw SYS_FSTAT (newfstat).
// This is an fd_event, so ior resolves the path via its fd lookup table.
func statFstat() error {
	dir, cleanup, err := makeTempDir("stat-fstat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fstatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	var stat syscall.Stat_t
	_, _, errno := syscall.Syscall(syscall.SYS_FSTAT, uintptr(fd), uintptr(unsafe.Pointer(&stat)), 0)
	runtime.KeepAlive(&stat)
	if errno != 0 {
		return fmt.Errorf("fstat: %w", errno)
	}
	return nil
}

// statLstat creates a file and stats it via raw SYS_LSTAT (newlstat).
// We use the raw syscall because Go's syscall.Lstat wraps newfstatat on amd64.
func statLstat() error {
	dir, cleanup, err := makeTempDir("stat-lstat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "lstatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	var stat syscall.Stat_t
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_LSTAT, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(&stat)), 0)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&stat)
	if errno != 0 {
		return fmt.Errorf("lstat: %w", errno)
	}
	return nil
}

// statNewfstatat creates a file and stats it via Go's syscall.Stat, which
// wraps SYS_NEWFSTATAT (fstatat with AT_FDCWD) on amd64.
func statNewfstatat() error {
	dir, cleanup, err := makeTempDir("stat-newfstatat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fstatatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return fmt.Errorf("newfstatat: %w", err)
	}
	return nil
}

// statStatx creates a file and stats it via raw statx(2) syscall.
func statStatx() error {
	dir, cleanup, err := makeTempDir("stat-statx")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "statxfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	var buf [256]byte // statx struct is ~256 bytes
	_, _, errno := syscall.Syscall6(
		sysStatx,
		^uintptr(99), // AT_FDCWD (-100)
		uintptr(unsafe.Pointer(pathBytes)),
		0,
		statxBasicMask,
		uintptr(unsafe.Pointer(&buf[0])),
		0,
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("statx: %w", errno)
	}
	return nil
}

// statAccess creates a file and checks access via raw SYS_ACCESS.
// We use the raw syscall because Go's syscall.Access wraps faccessat on amd64.
func statAccess() error {
	dir, cleanup, err := makeTempDir("stat-access")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "accessfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_ACCESS, uintptr(unsafe.Pointer(pathBytes)), rOK, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("access: %w", errno)
	}
	return nil
}

// statFaccessat creates a file and checks access via faccessat(2).
// Go's syscall.Faccessat wraps SYS_FACCESSAT.
func statFaccessat() error {
	dir, cleanup, err := makeTempDir("stat-faccessat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "faccessatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	if err := syscall.Faccessat(atFDCwd, path, uint32(rOK), 0); err != nil {
		return fmt.Errorf("faccessat: %w", err)
	}
	return nil
}

// statEnoent attempts to stat a nonexistent file via raw SYS_STAT.
// The syscall fails with ENOENT, but ior captures the enter_newstat
// tracepoint because the filename is read on entry.
func statEnoent() error {
	dir, cleanup, err := makeTempDir("stat-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "stat-enoent-missing.txt")
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	var stat syscall.Stat_t
	// Retry a few times to reduce dropped-event flakiness under high parallelism.
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_STAT, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(&stat)), 0)
		runtime.KeepAlive(pathBytes)
		runtime.KeepAlive(&stat)
		if errno == 0 {
			return fmt.Errorf("expected ENOENT, but stat succeeded")
		}
	}
	return nil
}

// statAccessEnoent attempts to check access on a nonexistent file via raw
// SYS_ACCESS. The syscall fails with ENOENT, but ior captures the
// enter_access tracepoint because the path is read on entry.
// We use ENOENT instead of EACCES because integration tests run as root,
// which bypasses DAC permission checks.
func statAccessEnoent() error {
	dir, cleanup, err := makeTempDir("stat-access-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "access-enoent-missing.txt")
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_ACCESS, uintptr(unsafe.Pointer(pathBytes)), rOK, 0)
		runtime.KeepAlive(pathBytes)
		if errno == 0 {
			return fmt.Errorf("expected ENOENT, but access succeeded")
		}
	}
	return nil
}

// statFstatEbadf calls raw SYS_FSTAT on an invalid fd (99999).
// The syscall fails with EBADF, but ior captures the enter_newfstat
// tracepoint because it is recorded on syscall entry.
func statFstatEbadf() error {
	var stat syscall.Stat_t
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FSTAT, 99999, uintptr(unsafe.Pointer(&stat)), 0)
		runtime.KeepAlive(&stat)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but fstat succeeded")
		}
	}
	return nil
}
