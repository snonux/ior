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
	sysIoSetup     = 206
	sysIoDestroy   = 207
	sysIoGetevents = 208
	sysIoSubmit    = 209
	sysIoCancel    = 210

	// aioMaxEvents is the nr_events count requested from io_setup(2). It is a
	// plain count (NOT an fd), so the tracer must classify the enter event as
	// KindNull and capture no fd/path argument.
	aioMaxEvents = 32

	// iocbCmdPwrite is IOCB_CMD_PWRITE from <linux/aio_abi.h>: the iocb opcode
	// requesting a positional write. io_submit submits iocbs carrying this
	// opcode; the tracer captures none of the iocb contents.
	iocbCmdPwrite = 1
)

// ioEvent mirrors struct io_event from <linux/aio_abi.h> on x86_64 (32 bytes).
// io_getevents(2) fills an array of these from the completion ring; we only
// need the layout to reap a completion, not to trace it (io_getevents args are
// opaque to the tracer, KindNull).
type ioEvent struct {
	data uint64 // 0: aio_data echoed from the submitting iocb
	obj  uint64 // 8: pointer to the originating iocb
	res  int64  // 16: primary result (bytes transferred, or -errno)
	res2 int64  // 24: secondary result
}

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
	return withAioTarget("aio-submit", func(ctx uint64, fd int) error {
		_, err := ioSubmitWrite(ctx, fd)
		return err
	})
}

// aioGetevents exercises io_getevents(2) end-to-end: it submits one iocb, then
// reaps its completion with io_getevents(ctx, min_nr, nr, events, timeout)
// (sys nr 208 on x86_64). This drives a real io_getevents tracepoint so the
// integration harness can validate enter_io_getevents/exit_io_getevents for the
// AIO family. io_getevents returns the COUNT of events reaped (not a byte
// count), which is why the tracer classifies its return UNCLASSIFIED.
func aioGetevents() error {
	return withAioTarget("aio-getevents", func(ctx uint64, fd int) error {
		if _, err := ioSubmitWrite(ctx, fd); err != nil {
			return err
		}
		return ioGeteventsReap(ctx)
	})
}

// aioCancel exercises io_cancel(2): it submits one iocb and then calls
// io_cancel(ctx, iocbp, &result) (sys nr 210 on x86_64). io_cancel is
// non-deterministic — the I/O frequently completes before the cancel runs, so
// the syscall often returns -EINVAL/-EAGAIN — but the enter_io_cancel
// tracepoint fires regardless of the return value, which is all the integration
// harness asserts on. To keep the context valid we still reap any pending
// completion with io_getevents afterwards before tearing down.
func aioCancel() error {
	return withAioTarget("aio-cancel", func(ctx uint64, fd int) error {
		cbp, err := ioSubmitWrite(ctx, fd)
		if err != nil {
			return err
		}
		// Best-effort cancel: ignore the (non-deterministic) return value;
		// only the enter tracepoint matters for coverage.
		ioCancelRequest(ctx, cbp)
		// Drain any pending completion non-blockingly so io_destroy has
		// nothing left in flight. We must NOT block here: if the cancel
		// succeeded the request produces no completion event, so a blocking
		// (min_nr=1) reap would hang.
		ioGeteventsDrain(ctx)
		return nil
	})
}

// withAioTarget sets up the common AIO scaffolding shared by the submit-based
// scenarios: a temp dir, a writable target file, and an AIO context. It invokes
// fn with the context id and the target fd, then tears the context and temp dir
// down. Factoring this out keeps the individual scenarios short.
func withAioTarget(label string, fn func(ctx uint64, fd int) error) error {
	dir, cleanup, err := makeTempDir(label)
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

	return fn(ctx, int(f.Fd()))
}

// ioSubmitWrite submits one IOCB_CMD_PWRITE iocb against fd via io_submit(2).
// io_submit takes (ctx_id, nr, iocbpp): an aio_context_t handle (NOT an fd), a
// count, and a userspace array of iocb pointers. On success it returns the
// number of iocbs accepted (1 here) and the submitted iocb pointer, which
// io_cancel(2) needs to identify the request to cancel.
func ioSubmitWrite(ctx uint64, fd int) (*iocb, error) {
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
		return nil, fmt.Errorf("io_submit: %w", errno)
	}
	if ret != uintptr(len(cbs)) {
		return nil, fmt.Errorf("io_submit submitted %d iocbs, want %d", ret, len(cbs))
	}
	return cbp, nil
}

// ioGeteventsReap reaps up to one completion from the AIO context with
// io_getevents(2). It takes (ctx_id, min_nr, nr, events, timeout): we request
// at least one event (min_nr=1) and a NULL timeout so the call blocks until the
// submitted write completes. The aio_context_t handle is NOT an fd and the
// events/timeout pointers are opaque to the tracer (KindNull enter); the return
// is a COUNT of events reaped (UNCLASSIFIED), not a byte count.
func ioGeteventsReap(ctx uint64) error {
	var events [1]ioEvent
	ret, _, errno := syscall.Syscall6(
		sysIoGetevents,
		uintptr(ctx),
		1, // min_nr: block until at least one completion is ready
		uintptr(len(events)),
		uintptr(unsafe.Pointer(&events[0])),
		0, // timeout: NULL -> wait indefinitely
		0,
	)
	runtime.KeepAlive(events)
	if errno != 0 {
		return fmt.Errorf("io_getevents: %w", errno)
	}
	if ret < 1 {
		return fmt.Errorf("io_getevents reaped %d events, want >= 1", ret)
	}
	return nil
}

// ioGeteventsDrain reaps any already-completed events non-blockingly
// (min_nr=0, NULL timeout) and discards them. It is used by the cancel scenario
// to clear the completion ring without risking a hang when the cancel succeeded
// and left no completion behind. Errors are ignored: this is best-effort
// cleanup, not a tracepoint-bearing assertion path.
func ioGeteventsDrain(ctx uint64) {
	var events [1]ioEvent
	_, _, _ = syscall.Syscall6(
		sysIoGetevents,
		uintptr(ctx),
		0, // min_nr=0: return immediately even if nothing is ready
		uintptr(len(events)),
		uintptr(unsafe.Pointer(&events[0])),
		0, // timeout: NULL
		0,
	)
	runtime.KeepAlive(events)
}

// ioCancelRequest attempts to cancel the in-flight iocb via io_cancel(2),
// which takes (ctx_id, iocb, result). The result io_event receives the
// completion data on a successful cancel. The return value is intentionally
// ignored by callers: io_cancel races the I/O completion and commonly fails
// with -EINVAL/-EAGAIN, but the enter_io_cancel tracepoint fires regardless,
// which is the only thing the integration harness asserts on.
func ioCancelRequest(ctx uint64, cbp *iocb) {
	var result ioEvent
	_, _, _ = syscall.Syscall(
		sysIoCancel,
		uintptr(ctx),
		uintptr(unsafe.Pointer(cbp)),
		uintptr(unsafe.Pointer(&result)),
	)
	runtime.KeepAlive(cbp)
	runtime.KeepAlive(result)
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
