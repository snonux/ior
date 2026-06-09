package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const mremapMayMove = 1

// mmapBasic creates a file-backed shared mapping.
// mmap(2) allows closing the fd after mapping without invalidating the mapping.
func mmapBasic() error {
	dir, cleanup, err := makeTempDir("mmap-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "mmapfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("mmap shared page data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	mapped, err := syscall.Mmap(fd, 0, len(data), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(mapped)

	copy(mapped[:4], []byte("MMAP"))
	return nil
}

// mmapMsyncSync maps a file and flushes modifications via msync(2).
// Per msync(2), callers should specify exactly one of MS_SYNC or MS_ASYNC.
func mmapMsyncSync() error {
	dir, cleanup, err := makeTempDir("mmap-msync-sync")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "msyncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("msync shared page data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	mapped, err := syscall.Mmap(fd, 0, len(data), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(mapped)

	copy(mapped[:5], []byte("MSYNC"))

	_, _, errno := syscall.Syscall(syscall.SYS_MSYNC, uintptr(unsafe.Pointer(&mapped[0])), uintptr(len(mapped)), uintptr(syscall.MS_SYNC))
	if errno != 0 {
		return fmt.Errorf("msync: %w", errno)
	}
	return nil
}

// mmapMsyncInvalidFlags calls msync(2) with both MS_SYNC and MS_ASYNC.
// The kernel returns EINVAL, but enter_msync should still be captured.
func mmapMsyncInvalidFlags() error {
	dir, cleanup, err := makeTempDir("mmap-msync-invalid-flags")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "msyncinvalidfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("msync invalid flags data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	mapped, err := syscall.Mmap(fd, 0, len(data), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(mapped)

	flags := syscall.MS_SYNC | syscall.MS_ASYNC
	_, _, errno := syscall.Syscall(syscall.SYS_MSYNC, uintptr(unsafe.Pointer(&mapped[0])), uintptr(len(mapped)), uintptr(flags))
	if errno != syscall.EINVAL {
		return fmt.Errorf("expected EINVAL from msync with both MS_SYNC|MS_ASYNC, got %v", errno)
	}
	return nil
}

// mmapMremapMunmap remaps an anonymous mapping and unmaps the resized region.
// It is used to validate enter_mremap/enter_munmap tracing and memory-byte
// accounting separation from I/O bytes.
func mmapMremapMunmap() error {
	const pageSize = 4096

	mapped, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}

	oldAddr := uintptr(unsafe.Pointer(&mapped[0]))
	newSize := uintptr(pageSize * 2)
	newAddr, _, errno := syscall.Syscall6(syscall.SYS_MREMAP, oldAddr, uintptr(len(mapped)), newSize, mremapMayMove, 0, 0)
	if errno != 0 {
		_ = syscall.Munmap(mapped)
		return fmt.Errorf("mremap: %w", errno)
	}

	_, _, errno = syscall.Syscall(syscall.SYS_MUNMAP, newAddr, newSize, 0)
	if errno != 0 {
		return fmt.Errorf("munmap: %w", errno)
	}
	return nil
}

// mmapMemoryLock exercises the memory-locking cluster (mlock, mlock2, munlock,
// mlockall, munlockall — all FamilyMemory) so the integration suite captures
// their sys_enter_ tracepoints end-to-end.
//
// All locking is done on a single anonymous page (one page = small enough to
// stay well under RLIMIT_MEMLOCK for an unprivileged process). The raw syscall
// path is used throughout so the exact tracepoints fire:
//   - mlock(addr, len) / munlock(addr, len)   -> KindMem (captures addr+len)
//   - mlock2(addr, len, 0)                     -> KindMem (no stdlib wrapper)
//   - mlockall(MCL_CURRENT) / munlockall()     -> KindNull
//
// Errors from mlock/mlock2/mlockall are tolerated best-effort: even when the
// kernel rejects the call (e.g. EPERM/ENOMEM if RLIMIT_MEMLOCK is too low), the
// sys_enter_ tracepoint has already fired, which is all this scenario needs.
// munlock/munlockall always succeed, so we clean up unconditionally.
func mmapMemoryLock() error {
	const pageSize = 4096

	mapped, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(mapped)

	addr := uintptr(unsafe.Pointer(&mapped[0]))
	length := uintptr(len(mapped))

	// mlock then munlock the single page (KindMem). EPERM/ENOMEM are tolerated:
	// the enter tracepoint fires regardless of the eventual errno.
	if _, _, errno := unix.Syscall(unix.SYS_MLOCK, addr, length, 0); errno != 0 && errno != syscall.EPERM && errno != syscall.ENOMEM {
		return fmt.Errorf("mlock: %w", errno)
	}
	if _, _, errno := unix.Syscall(unix.SYS_MUNLOCK, addr, length, 0); errno != 0 {
		return fmt.Errorf("munlock: %w", errno)
	}

	// mlock2(addr, len, 0) has no stdlib/x-sys wrapper; issue the raw syscall.
	if _, _, errno := unix.Syscall(unix.SYS_MLOCK2, addr, length, 0); errno != 0 && errno != syscall.EPERM && errno != syscall.ENOMEM {
		return fmt.Errorf("mlock2: %w", errno)
	}
	// Drop any lock established by mlock2 before unmapping.
	if _, _, errno := unix.Syscall(unix.SYS_MUNLOCK, addr, length, 0); errno != 0 {
		return fmt.Errorf("munlock after mlock2: %w", errno)
	}

	// mlockall(MCL_CURRENT) then munlockall() (KindNull). mlockall may fail with
	// EPERM/ENOMEM for unprivileged callers when RLIMIT_MEMLOCK is too low; its
	// enter tracepoint still fires. munlockall always succeeds.
	if _, _, errno := unix.Syscall(unix.SYS_MLOCKALL, uintptr(unix.MCL_CURRENT), 0, 0); errno != 0 && errno != syscall.EPERM && errno != syscall.ENOMEM {
		return fmt.Errorf("mlockall: %w", errno)
	}
	if _, _, errno := unix.Syscall(unix.SYS_MUNLOCKALL, 0, 0, 0); errno != 0 {
		return fmt.Errorf("munlockall: %w", errno)
	}
	return nil
}
