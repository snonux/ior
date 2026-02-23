package main

import (
	"fmt"
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
