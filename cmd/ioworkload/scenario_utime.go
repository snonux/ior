package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// utimbuf mirrors struct utimbuf from <utime.h>: the actime/modtime pair that
// utime(2) reads from userspace. It is passed by pointer as the second arg.
type utimbuf struct {
	actime  int64 // access time (seconds)
	modtime int64 // modification time (seconds)
}

// timeval mirrors struct timeval used by utimes(2): a 2-element array of
// {tv_sec, tv_usec} for the new access and modification times.
type timeval struct {
	tvSec  int64
	tvUsec int64
}

// utimeBasic creates a file and changes its timestamps via raw SYS_UTIME.
// utime(2) takes a real filesystem path at args[0] ("filename"), so ior must
// capture it as a path event (KindPathname) and tag it FamilyFS, matching its
// siblings utimensat/futimesat. We use the raw syscall because Go's os.Chtimes
// wraps utimensat on amd64, not utime.
func utimeBasic() error {
	dir, cleanup, err := makeTempDir("utime-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "utimefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	times := utimbuf{actime: 1000000000, modtime: 1000000000}
	_, _, errno := syscall.Syscall(
		syscall.SYS_UTIME,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&times)),
		0,
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&times)
	if errno != 0 {
		return fmt.Errorf("utime: %w", errno)
	}
	return nil
}

// utimeUtimes creates a file and changes its timestamps via raw SYS_UTIMES.
// utimes(2) is utime's microsecond-resolution sibling and likewise takes a
// real path at args[0] ("filename"), so it is path-classified and FamilyFS.
func utimeUtimes() error {
	dir, cleanup, err := makeTempDir("utime-utimes")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "utimesfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	times := [2]timeval{
		{tvSec: 1000000000, tvUsec: 0},
		{tvSec: 1000000000, tvUsec: 0},
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_UTIMES,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&times[0])),
		0,
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&times)
	if errno != 0 {
		return fmt.Errorf("utimes: %w", errno)
	}
	return nil
}

// timespec mirrors struct timespec used by utimensat(2): a {tv_sec, tv_nsec}
// pair. utimensat takes a 2-element array for the new access and modification
// times.
type timespec struct {
	tvSec  int64
	tvNsec int64
}

// utimeFutimesat creates a file and changes its timestamps via raw
// SYS_FUTIMESAT. futimesat(2) takes a dirfd at args[0] and a pathname at
// args[1] ("filename"), so ior must capture the path from args[1] (after the
// dirfd), classify it as a path event (KindPathname), and tag it FamilyFS like
// its siblings utime/utimes/utimensat. We pass AT_FDCWD as the dirfd so the
// absolute path resolves relative to the cwd, and a 2-element timeval array to
// set explicit times. The raw syscall guarantees the exact enter_futimesat
// tracepoint fires.
func utimeFutimesat() error {
	dir, cleanup, err := makeTempDir("utime-futimesat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "futimesatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	times := [2]timeval{
		{tvSec: 1000000000, tvUsec: 0},
		{tvSec: 1000000000, tvUsec: 0},
	}
	// Use a runtime int variable so the negative AT_FDCWD survives the uintptr
	// conversion: converting the negative constant directly overflows uintptr.
	dirfd := _AT_FDCWD
	_, _, errno := syscall.Syscall(
		syscall.SYS_FUTIMESAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&times[0])),
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&times)
	if errno != 0 {
		return fmt.Errorf("futimesat: %w", errno)
	}
	return nil
}

// utimeUtimensat creates a file and changes its timestamps via raw
// SYS_UTIMENSAT. utimensat(2) is the nanosecond-resolution sibling: it takes a
// dirfd at args[0] and a pathname at args[1] ("filename"), so the path must be
// captured from args[1] (after the dirfd) and is path-classified and FamilyFS.
// We pass AT_FDCWD as the dirfd, a 2-element timespec array for the times, and
// 0 for flags. The raw syscall guarantees the exact enter_utimensat tracepoint
// fires (Go's os.Chtimes also wraps utimensat, but going raw keeps the dirfd
// and arg layout explicit).
func utimeUtimensat() error {
	dir, cleanup, err := makeTempDir("utime-utimensat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "utimensatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	times := [2]timespec{
		{tvSec: 1000000000, tvNsec: 0},
		{tvSec: 1000000000, tvNsec: 0},
	}
	// Use a runtime int variable so the negative AT_FDCWD survives the uintptr
	// conversion: converting the negative constant directly overflows uintptr.
	dirfd := _AT_FDCWD
	_, _, errno := syscall.Syscall6(
		syscall.SYS_UTIMENSAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&times[0])),
		0, // flags
		0, 0,
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&times)
	if errno != 0 {
		return fmt.Errorf("utimensat: %w", errno)
	}
	return nil
}

// utimeEnoent calls raw SYS_UTIME on a nonexistent path. The syscall fails
// with ENOENT, but ior still captures the enter_utime tracepoint because the
// filename path is read on syscall entry. This locks in that the path is
// captured even on the error path.
func utimeEnoent() error {
	dir, cleanup, err := makeTempDir("utime-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "utime-enoent-missing.txt")
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	times := utimbuf{actime: 1000000000, modtime: 1000000000}
	// Retry a few times to reduce dropped-event flakiness under high parallelism.
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(
			syscall.SYS_UTIME,
			uintptr(unsafe.Pointer(pathBytes)),
			uintptr(unsafe.Pointer(&times)),
			0,
		)
		runtime.KeepAlive(pathBytes)
		runtime.KeepAlive(&times)
		if errno == 0 {
			return fmt.Errorf("expected ENOENT, but utime succeeded")
		}
		if i < 4 {
			time.Sleep(statRetryDelay)
		}
	}
	return nil
}
