package internal

import (
	"syscall"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// io_uring ABI bits that turn the descriptor of a call into an index into the
// task's registered-ring table (<linux/io_uring.h>; golang.org/x/sys/unix does
// not export them).
const (
	// ioringEnterRegisteredRing is IORING_ENTER_REGISTERED_RING, a bit of the
	// io_uring_enter flags word: fd is a registered-ring index.
	ioringEnterRegisteredRing = 1 << 4
	// ioringRegisterUseRegisteredRing is IORING_REGISTER_USE_REGISTERED_RING,
	// OR-ed into the io_uring_register opcode: fd is a registered-ring index.
	ioringRegisterUseRegisteredRing = 1 << 31
	// ioringSetupRegisteredFdOnly is IORING_SETUP_REGISTERED_FD_ONLY, an
	// io_uring_params.flags bit: the ring is reachable only through the
	// registered-ring table, no descriptor is installed and the return value is
	// the table index.
	ioringSetupRegisteredFdOnly = 1 << 15
)

// handleIoUringExit finishes an io_uring_enter, io_uring_register or
// io_uring_setup pair. The three arrive as fcntl_event records because they
// need the word next to the descriptor - the enter flags, the register opcode
// or the setup flags (FcntlEvent.Cmd) - to know whether that number is a file
// descriptor at all.
//
// When it is a registered-ring index the row is labelled with the index and
// the fd table is neither consulted nor changed: looking the index up as a
// descriptor attributed the call to whatever file the process had at that fd
// (stdin for index 0), and registering a REGISTERED_FD_ONLY setup's return
// value as a descriptor overwrote that fd's real entry.
func (e *eventLoop) handleIoUringExit(ep *event.Pair, ev *types.FcntlEvent) bool {
	ep.Comm = e.comm(ev.GetTid())
	if ep.Is(types.SYS_ENTER_IO_URING_SETUP) {
		return e.handleIoUringSetupExit(ep, ev)
	}
	if ioUringFdIsRegisteredIndex(ev) {
		ep.File = file.NewRegisteredRing(int32(ev.Fd))
	} else {
		ep.File = e.fdState().resolve(int32(ev.Fd), ev.Pid)
	}
	return e.finishPair(ep)
}

// ioUringFdIsRegisteredIndex reports whether the descriptor argument of an
// io_uring_enter/io_uring_register call is a registered-ring index.
func ioUringFdIsRegisteredIndex(ev *types.FcntlEvent) bool {
	switch ev.TraceId {
	case types.SYS_ENTER_IO_URING_ENTER:
		return ev.Cmd&ioringEnterRegisteredRing != 0
	case types.SYS_ENTER_IO_URING_REGISTER:
		return ev.Cmd&ioringRegisterUseRegisteredRing != 0
	default:
		return false
	}
}

// handleIoUringSetupExit registers the ring descriptor a successful
// io_uring_setup returned, unless the ring was created with
// IORING_SETUP_REGISTERED_FD_ONLY: then the return value is a registered-ring
// index and there is no descriptor to register. A failed setup leaves the pair
// without a file, as before.
func (e *eventLoop) handleIoUringSetupExit(ep *event.Pair, ev *types.FcntlEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed io_uring_setup exit event")
		return false
	}
	ret, ok := fdFromRet(retEvent.Ret)
	if !ok {
		return e.finishPair(ep)
	}
	if ev.Cmd&ioringSetupRegisteredFdOnly != 0 {
		ep.File = file.NewRegisteredRing(ret)
		return e.finishPair(ep)
	}
	fdFile := file.NewFdWithPid(ret, ev.Pid)
	if fdFile.Flags() == file.Flags(-1) {
		fdFile.SetFlags(syscall.O_RDWR | syscall.O_CLOEXEC)
	}
	e.fdState().set(ret, ev.Pid, fdFile)
	ep.File = fdFile
	return e.finishPair(ep)
}
