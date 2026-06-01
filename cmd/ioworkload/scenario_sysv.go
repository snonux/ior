package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sysvShmPayload is written into the attached SysV shared-memory segment so the
// scenario touches the mapping (forcing a real page fault) rather than just
// attaching and detaching it.
var sysvShmPayload = []byte("ior-sysv-shm")

// sysvShmBasic exercises the SysV shared-memory family end-to-end without any
// privileges: it creates a private anonymous segment (shmget IPC_PRIVATE),
// attaches it (shmat), writes a few bytes into the mapped region, detaches it
// (shmdt), and finally removes it (shmctl IPC_RMID). IPC_RMID is always issued
// (even on a partial failure) so the test never leaks a kernel IPC object.
func sysvShmBasic() error {
	const segSize = 4096
	shmid, err := shmGet(segSize)
	if err != nil {
		return err
	}
	// Guarantee the segment is removed regardless of how the rest fares; an
	// orphaned IPC_PRIVATE segment would otherwise leak until reboot.
	defer func() { _ = shmRemove(shmid) }()

	addr, err := shmAttach(shmid)
	if err != nil {
		return err
	}
	if err := shmWrite(addr, segSize); err != nil {
		_ = shmDetach(addr)
		return err
	}
	if err := shmDetach(addr); err != nil {
		return err
	}
	return nil
}

// shmGet creates a new private SysV shared-memory segment of the given size and
// returns its identifier.
func shmGet(size uintptr) (uintptr, error) {
	shmid, _, errno := syscall.Syscall(
		syscall.SYS_SHMGET,
		uintptr(unix.IPC_PRIVATE),
		size,
		uintptr(unix.IPC_CREAT|0o600),
	)
	if errno != 0 {
		return 0, fmt.Errorf("shmget: %w", errno)
	}
	return shmid, nil
}

// shmAttach attaches the segment into the address space and returns its base
// address. shmflg 0 requests a read/write mapping at a kernel-chosen address.
func shmAttach(shmid uintptr) (uintptr, error) {
	addr, _, errno := syscall.Syscall(syscall.SYS_SHMAT, shmid, 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("shmat: %w", errno)
	}
	return addr, nil
}

// shmWrite copies the payload into the mapped segment, faulting the page in so
// the workload genuinely uses the shared memory.
func shmWrite(addr, size uintptr) error {
	if uintptr(len(sysvShmPayload)) > size {
		return fmt.Errorf("shm payload (%d) exceeds segment size (%d)", len(sysvShmPayload), size)
	}
	seg := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(sysvShmPayload))
	copy(seg, sysvShmPayload)
	return nil
}

// shmDetach detaches the previously attached segment from the address space.
func shmDetach(addr uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_SHMDT, addr, 0, 0)
	if errno != 0 {
		return fmt.Errorf("shmdt: %w", errno)
	}
	return nil
}

// shmRemove marks the segment for destruction (IPC_RMID); the kernel frees it
// once the last attachment is gone.
func shmRemove(shmid uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_SHMCTL, shmid, uintptr(unix.IPC_RMID), 0)
	if errno != 0 {
		return fmt.Errorf("shmctl IPC_RMID: %w", errno)
	}
	return nil
}
