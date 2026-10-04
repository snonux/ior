package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	ioringUnregisterRingFds = 21 // IORING_UNREGISTER_RING_FDS

	// ioUringLifecycleDecoyPrefix names the file the lifecycle scenario opens
	// on the ring's descriptor number once the ring's descriptor is closed.
	ioUringLifecycleDecoyPrefix = "ioworkload-iouring-reuse-"

	// Calls per phase of iouring-ring-lifecycle; the integration
	// test tells the phases apart by these counts.
	ioUringLifecycleOpenCalls   = 3
	ioUringLifecycleClosedCalls = 4
	ioUringLifecycleGoneCalls   = 2
)

// iouringRegisteredRingLifecycle walks one registered ring through what a
// tracer has to follow to name the rows that address it by index (task js2):
//
//  1. the ring is registered - from an array that ends where its mapping
//     ends - and entered by index while its descriptor is open
//     (ioUringLifecycleOpenCalls times);
//  2. the descriptor is closed and its number reused by a decoy file; the
//     registered ring stays usable and is entered ioUringLifecycleClosedCalls
//     times more. Those rows are the ring's, not the decoy's;
//  3. another thread, which registered nothing, passes the same index: its
//     table is its own, and the kernel refuses the call;
//  4. the index is unregistered - by a call that itself addresses the ring by
//     that index - and entered ioUringLifecycleGoneCalls times more, which
//     the kernel answers with EBADF.
//
// The registered-ring table belongs to the calling thread, so the goroutine
// is pinned to one OS thread for the whole scenario.
func iouringRegisteredRingLifecycle() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	index, err := registerRingFdAtMappingEnd(fd)
	if err != nil {
		syscall.Close(fd)
		return err
	}
	if err := enterRegisteredRing(index, ioUringLifecycleOpenCalls, 0); err != nil {
		syscall.Close(fd)
		return err
	}
	decoy, err := reuseDescriptorNumber(fd)
	if err != nil {
		return err
	}
	defer syscall.Close(decoy)
	if err := enterRegisteredRing(index, ioUringLifecycleClosedCalls, 0); err != nil {
		return err
	}
	if err := enterRegisteredRingOnAnotherThread(index); err != nil {
		return err
	}
	if err := unregisterRingByIndex(index); err != nil {
		return err
	}
	return enterRegisteredRing(index, ioUringLifecycleGoneCalls, syscall.EBADF)
}

// registerRingFdAtMappingEnd is registerRingFd with the one-element array in
// the last bytes of a mapping whose next page is inaccessible. The kernel
// reads and writes just that element; a tracer that reads more than the
// entries the call processed gets a fault instead of the array.
func registerRingFdAtMappingEnd(ring int) (uint32, error) {
	page := os.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, 2*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return 0, fmt.Errorf("mmap array: %w", err)
	}
	defer syscall.Munmap(mem)
	if err := syscall.Mprotect(mem[page:], syscall.PROT_NONE); err != nil {
		return 0, fmt.Errorf("mprotect guard page: %w", err)
	}
	update := (*ioUringRsrcUpdate)(unsafe.Pointer(&mem[page-int(unsafe.Sizeof(ioUringRsrcUpdate{}))]))
	*update = ioUringRsrcUpdate{offset: ^uint32(0), data: uint64(ring)}
	n, _, errno := syscall.Syscall6(sysIoUringRegister, uintptr(ring), ioringRegisterRingFds,
		uintptr(unsafe.Pointer(update)), 1, 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("io_uring_register(RING_FDS): %w", errno)
	}
	if n != 1 {
		return 0, fmt.Errorf("io_uring_register(RING_FDS) registered %d entries, want 1", n)
	}
	return update.offset, nil
}

// enterRegisteredRing calls io_uring_enter through the registered-ring index
// times times and requires each call to end with want (0: success).
func enterRegisteredRing(index uint32, times int, want syscall.Errno) error {
	for range times {
		_, _, errno := syscall.Syscall6(sysIoUringEnter, uintptr(index), 0, 0, ioringEnterRegisteredRing, 0, 0)
		if errno != want {
			return fmt.Errorf("io_uring_enter(registered ring %d): errno %d, want %d", index, errno, want)
		}
	}
	return nil
}

// reuseDescriptorNumber closes the ring descriptor fd and opens a decoy file
// on the same number, which it returns. The number is the lowest free one
// right after the close, so a plain open lands on it; should something else
// have taken it, the decoy is moved there.
func reuseDescriptorNumber(fd int) (int, error) {
	f, err := os.CreateTemp("", ioUringLifecycleDecoyPrefix)
	if err != nil {
		return 0, fmt.Errorf("create decoy: %w", err)
	}
	// os.RemoveAll is the teardown call the lint config exempts here; the
	// descriptor opened below keeps the file alive.
	defer os.RemoveAll(f.Name())
	defer func() { _ = f.Close() }()
	if err := syscall.Close(fd); err != nil {
		return 0, fmt.Errorf("close ring fd %d: %w", fd, err)
	}
	decoy, err := syscall.Open(f.Name(), syscall.O_RDONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("open decoy: %w", err)
	}
	if decoy == fd {
		return fd, nil
	}
	defer syscall.Close(decoy)
	if err := syscall.Dup3(decoy, fd, 0); err != nil {
		return 0, fmt.Errorf("dup3 decoy onto fd %d: %w", fd, err)
	}
	return fd, nil
}

// enterRegisteredRingOnAnotherThread passes index to io_uring_enter on an OS
// thread that never registered a ring. The kernel must refuse it: EINVAL for
// a thread without an io_uring context, EBADF for one with an empty slot.
func enterRegisteredRingOnAnotherThread(index uint32) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, _, errno := syscall.Syscall6(sysIoUringEnter, uintptr(index), 0, 0, ioringEnterRegisteredRing, 0, 0)
		if errno != syscall.EINVAL && errno != syscall.EBADF {
			done <- fmt.Errorf("io_uring_enter(index %d) on another thread: errno %d, want EINVAL or EBADF", index, errno)
			return
		}
		done <- nil
	}()
	return <-done
}

// unregisterRingByIndex releases the registered-ring slot index with a call
// that addresses the ring by that same index, as liburing does once the ring
// descriptor is registered.
func unregisterRingByIndex(index uint32) error {
	update := ioUringRsrcUpdate{offset: index}
	n, _, errno := syscall.Syscall6(sysIoUringRegister, uintptr(index),
		ioringUnregisterRingFds|ioringRegisterUseRegisteredRing,
		uintptr(unsafe.Pointer(&update)), 1, 0, 0)
	runtime.KeepAlive(&update)
	if errno != 0 {
		return fmt.Errorf("io_uring_register(UNREGISTER_RING_FDS): %w", errno)
	}
	if n != 1 {
		return errors.New("io_uring_register(UNREGISTER_RING_FDS) released no entry")
	}
	return nil
}
