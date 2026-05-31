package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	sysIoSubmit  = 209

	// aioMaxEvents is the nr_events count requested from io_setup(2). It is a
	// plain count (NOT an fd), so the tracer must classify the enter event as
	// KindNull and capture no fd/path argument.
	aioMaxEvents = 32

	// iocbCmdPwrite is IOCB_CMD_PWRITE from <linux/aio_abi.h>: the iocb opcode
	// requesting a positional write. io_submit submits iocbs carrying this
	// opcode; the tracer captures none of the iocb contents.
	iocbCmdPwrite = 1
)

// iocb mirrors struct iocb from <linux/aio_abi.h> on x86_64 (64 bytes). It is
// the control block io_submit(2) consumes via its iocbpp pointer-array argument.
// The tracer treats io_submit's args (ctx_id, nr, iocbpp) as opaque (KindNull),
// so this layout matters only for driving a real submission, not for tracing.
type iocb struct {
	aioData       uint64 // 0: opaque user data echoed back in the completion
	aioKeyRWFlags uint64 // 8: aio_key (lo32) + aio_rw_flags (hi32)
	aioLioOpcode  uint16 // 16: IOCB_CMD_* opcode
	aioReqprio    int16  // 18: request priority
	aioFildes     uint32 // 20: target file descriptor
	aioBuf        uint64 // 24: userspace data buffer pointer
	aioNbytes     uint64 // 32: byte count
	aioOffset     int64  // 40: file offset
	aioReserved2  uint64 // 48: reserved, must be zero
	aioFlags      uint32 // 56: IOCB_FLAG_* flags
	aioResfd      uint32 // 60: eventfd for completion notification
}

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

// aioSubmit exercises io_submit(2) end-to-end: it sets up an AIO context,
// submits a single positional-write iocb against a temp file, then tears the
// context down. This drives a real io_submit tracepoint so the integration
// harness can validate that ior records enter_io_submit/exit_io_submit for the
// AIO family. Note io_submit returns the COUNT of iocbs submitted (here 1), NOT
// a byte count, which is why the tracer must classify its return UNCLASSIFIED.
func aioSubmit() error {
	dir, cleanup, err := makeTempDir("aio-submit")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "aio-target")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open aio target: %w", err)
	}
	defer f.Close()

	ctx, err := ioSetupContext(aioMaxEvents)
	if err != nil {
		return err
	}
	defer ioDestroyContext(ctx)

	return ioSubmitWrite(ctx, int(f.Fd()))
}

// ioSubmitWrite submits one IOCB_CMD_PWRITE iocb against fd via io_submit(2).
// io_submit takes (ctx_id, nr, iocbpp): an aio_context_t handle (NOT an fd), a
// count, and a userspace array of iocb pointers. On success it returns the
// number of iocbs accepted (1 here).
func ioSubmitWrite(ctx uint64, fd int) error {
	buf := []byte("ior-aio-submit\n")
	cb := iocb{
		aioLioOpcode: iocbCmdPwrite,
		aioFildes:    uint32(fd),
		aioBuf:       uint64(uintptr(unsafe.Pointer(&buf[0]))),
		aioNbytes:    uint64(len(buf)),
		aioOffset:    0,
	}
	cbp := &cb
	cbs := []*iocb{cbp}

	ret, _, errno := syscall.Syscall(
		sysIoSubmit,
		uintptr(ctx),
		uintptr(len(cbs)),
		uintptr(unsafe.Pointer(&cbs[0])),
	)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(cbp)
	if errno != 0 {
		return fmt.Errorf("io_submit: %w", errno)
	}
	if ret != uintptr(len(cbs)) {
		return fmt.Errorf("io_submit submitted %d iocbs, want %d", ret, len(cbs))
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
