package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427

	// io_uring_params struct size: 10 x uint32 + io_sqring_offsets(40) + io_cqring_offsets(40) = 120 bytes.
	ioUringParamsSize = 120

	ioringRegisterProbe = 8 // IORING_REGISTER_PROBE
)

// iouringSetup creates an io_uring instance via io_uring_setup(2) and closes the fd.
func iouringSetup() error {
	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}

// iouringEnter creates an io_uring instance, then calls io_uring_enter(2)
// with zero submissions/completions to exercise the enter tracepoint.
func iouringEnter() error {
	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	_, _, errno := syscall.Syscall6(
		sysIoUringEnter,
		uintptr(fd),
		0, // to_submit
		0, // min_complete
		0, // flags
		0, // sig
		0, // sz
	)
	if errno != 0 {
		return fmt.Errorf("io_uring_enter: %w", errno)
	}
	return nil
}

// iouringRegister creates an io_uring instance, then calls io_uring_register(2)
// with IORING_REGISTER_PROBE to exercise the register tracepoint.
func iouringRegister() error {
	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// io_uring_probe header is 16 bytes; we don't need probe_op entries.
	var probeBuf [16]byte
	_, _, errno := syscall.Syscall6(
		sysIoUringRegister,
		uintptr(fd),
		ioringRegisterProbe,
		uintptr(unsafe.Pointer(&probeBuf[0])),
		0, // nr_args (0 ops requested)
		0, 0,
	)
	runtime.KeepAlive(probeBuf)
	if errno != 0 {
		return fmt.Errorf("io_uring_register: %w", errno)
	}
	return nil
}

// iouringEnterEbadf calls io_uring_enter on an invalid fd.
// The syscall fails with EBADF, but ior captures the enter_io_uring_enter tracepoint.
func iouringEnterEbadf() error {
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall6(
			sysIoUringEnter,
			99999, // invalid fd
			0,     // to_submit
			0,     // min_complete
			0,     // flags
			0,     // sig
			0,     // sz
		)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but io_uring_enter succeeded")
		}
	}
	return nil
}

// iouringRegisterEbadf calls io_uring_register on an invalid fd.
// The syscall fails with EBADF, but ior captures the enter_io_uring_register tracepoint.
func iouringRegisterEbadf() error {
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall6(
			sysIoUringRegister,
			99999, // invalid fd
			ioringRegisterProbe,
			0, // arg (NULL)
			0, // nr_args
			0, 0,
		)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but io_uring_register succeeded")
		}
	}
	return nil
}

// ioUringSetupRing calls io_uring_setup(2) and returns the ring fd.
func ioUringSetupRing(entries uint32) (int, error) {
	var params [ioUringParamsSize]byte
	fd, _, errno := syscall.Syscall(
		sysIoUringSetup,
		uintptr(entries),
		uintptr(unsafe.Pointer(&params[0])),
		0,
	)
	runtime.KeepAlive(params)
	if errno != 0 {
		return 0, fmt.Errorf("io_uring_setup: %w", errno)
	}
	return int(fd), nil
}

const (
	ioringRegisterRingFds           = 20      // IORING_REGISTER_RING_FDS
	ioringRegisterUseRegisteredRing = 1 << 31 // IORING_REGISTER_USE_REGISTERED_RING
	ioringEnterRegisteredRing       = 1 << 4  // IORING_ENTER_REGISTERED_RING

	// ioUringDecoyPrefix names the file the registered-ring scenario parks on
	// fd 0; the integration test asserts no io_uring row is attributed to it.
	ioUringDecoyPrefix = "ioworkload-iouring-decoy-"
)

// ioUringRsrcUpdate is struct io_uring_rsrc_update, the argument element of
// IORING_REGISTER_RING_FDS: offset is the registered-ring slot (-1 lets the
// kernel pick one and write it back), data is the ring descriptor.
type ioUringRsrcUpdate struct {
	offset uint32
	resv   uint32
	data   uint64
}

// iouringRegisteredRing drives io_uring_enter and io_uring_register through
// the registered-ring table, the way liburing does after
// io_uring_register_ring_fd(): the descriptor argument is then a small table
// index (typically 0), not a file descriptor. A decoy file is parked on fd 0 so
// that misreading the index as a descriptor is visible: such rows would be
// attributed to the decoy instead of the ring.
//
// The registered-ring table belongs to the calling thread, so the goroutine is
// pinned to one OS thread for the whole scenario.
func iouringRegisteredRing() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := parkDecoyOnFd0(); err != nil {
		return err
	}
	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	index, err := registerRingFd(fd)
	if err != nil {
		return err
	}
	for i := 0; i < 5; i++ {
		if _, _, errno := syscall.Syscall6(sysIoUringEnter, uintptr(index), 0, 0,
			ioringEnterRegisteredRing, 0, 0); errno != 0 {
			return fmt.Errorf("io_uring_enter(registered ring %d): %w", index, errno)
		}
		var probeBuf [16]byte
		if _, _, errno := syscall.Syscall6(sysIoUringRegister, uintptr(index),
			ioringRegisterProbe|ioringRegisterUseRegisteredRing,
			uintptr(unsafe.Pointer(&probeBuf[0])), 0, 0, 0); errno != 0 {
			return fmt.Errorf("io_uring_register(registered ring %d): %w", index, errno)
		}
		runtime.KeepAlive(probeBuf)
	}
	return nil
}

// registerRingFd registers ring in the thread's registered-ring table and
// returns the slot the kernel allocated.
func registerRingFd(ring int) (uint32, error) {
	update := ioUringRsrcUpdate{offset: ^uint32(0), data: uint64(ring)}
	n, _, errno := syscall.Syscall6(sysIoUringRegister, uintptr(ring), ioringRegisterRingFds,
		uintptr(unsafe.Pointer(&update)), 1, 0, 0)
	runtime.KeepAlive(&update)
	if errno != 0 {
		return 0, fmt.Errorf("io_uring_register(RING_FDS): %w", errno)
	}
	if n != 1 {
		return 0, fmt.Errorf("io_uring_register(RING_FDS) registered %d entries, want 1", n)
	}
	return update.offset, nil
}

// parkDecoyOnFd0 makes fd 0 refer to a freshly created regular file, so a
// registered-ring index 0 misread as a descriptor resolves to a known path.
func parkDecoyOnFd0() error {
	f, err := os.CreateTemp("", ioUringDecoyPrefix)
	if err != nil {
		return fmt.Errorf("create decoy: %w", err)
	}
	// fd 0 keeps the open file description alive, so the file can go now; its
	// /proc link then reads "<path> (deleted)", which still carries the prefix.
	// os.RemoveAll is the teardown call the lint config exempts in this package.
	defer os.RemoveAll(f.Name())
	defer func() { _ = f.Close() }()
	if err := syscall.Dup3(int(f.Fd()), 0, 0); err != nil {
		return fmt.Errorf("dup3 decoy onto fd 0: %w", err)
	}
	return nil
}
