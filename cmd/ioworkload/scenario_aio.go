package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// Linux AIO (io_setup family) syscall numbers on x86_64. These are the classic
// kernel AIO interface (io_setup/io_submit/io_getevents/io_cancel/io_destroy),
// distinct from the io_uring_* family. We invoke them raw via Syscall because
// the Go standard library does not wrap them.
const (
	sysIoSetup   = 206
	sysIoDestroy = 207

	// aioMaxEvents is the nr_events count requested from io_setup(2). It is a
	// plain count (NOT an fd), so the tracer must classify the enter event as
	// KindNull and capture no fd/path argument.
	aioMaxEvents = 32
)

// aioSetup exercises io_setup(2): it creates an AIO context (writing the
// context id into a userspace pointer) and then tears it down with
// io_destroy(2). io_setup needs no special privileges, so this runs end-to-end
// in the integration harness and validates that ior records the
// enter_io_setup/exit_io_setup tracepoints for the AIO family.
func aioSetup() error {
	ctx, err := ioSetupContext(aioMaxEvents)
	if err != nil {
		return err
	}
	return ioDestroyContext(ctx)
}

// aioSetupEinval calls io_setup(2) with nr_events = 0, which the kernel rejects
// with EINVAL. The syscall fails, but ior still captures the enter_io_setup
// tracepoint and an exit_io_setup return event carrying the negative errno.
func aioSetupEinval() error {
	for i := 0; i < 5; i++ {
		var ctx uint64
		_, _, errno := syscall.Syscall(
			sysIoSetup,
			0, // nr_events = 0 -> EINVAL
			uintptr(unsafe.Pointer(&ctx)),
			0,
		)
		runtime.KeepAlive(ctx)
		if errno == 0 {
			return fmt.Errorf("expected EINVAL, but io_setup(0) succeeded")
		}
	}
	return nil
}

// ioSetupContext calls io_setup(2) and returns the opaque aio_context_t id.
func ioSetupContext(nrEvents uint32) (uint64, error) {
	var ctx uint64
	_, _, errno := syscall.Syscall(
		sysIoSetup,
		uintptr(nrEvents),
		uintptr(unsafe.Pointer(&ctx)),
		0,
	)
	runtime.KeepAlive(ctx)
	if errno != 0 {
		return 0, fmt.Errorf("io_setup: %w", errno)
	}
	return ctx, nil
}

// ioDestroyContext tears down an AIO context created by io_setup(2).
func ioDestroyContext(ctx uint64) error {
	_, _, errno := syscall.Syscall(sysIoDestroy, uintptr(ctx), 0, 0)
	if errno != 0 {
		return fmt.Errorf("io_destroy: %w", errno)
	}
	return nil
}
