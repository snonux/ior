package internal

import (
	"fmt"
	"os"
	"syscall"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// handleTracepointExit routes a completed enter/exit pair to the appropriate
// handler using a type switch, avoiding reflection on the hot event path.
func (e *eventLoop) handleTracepointExit(ep *event.Pair) bool {
	switch ev := ep.EnterEv.(type) {
	case *types.OpenEvent:
		return e.handleOpenExit(ep, ev)
	case *types.NameEvent:
		return e.handleNameExit(ep, ev)
	case *types.PathEvent:
		return e.handlePathExit(ep, ev)
	case *types.FdEvent:
		return e.handleFdExit(ep, ev)
	case *types.Dup3Event:
		return e.handleDup3Exit(ep, ev)
	case *types.OpenByHandleAtEvent:
		return e.handleOpenByHandleAtExit(ep, ev)
	case *types.SocketEvent:
		return e.handleSocketExit(ep, ev)
	case *types.SocketpairEvent:
		return e.handleSocketpairExit(ep, ev)
	case *types.AcceptEvent:
		return e.handleAcceptExit(ep, ev)
	case *types.PipeEvent:
		return e.handlePipeExit(ep, ev)
	case *types.EventfdEvent:
		return e.handleEventfdExit(ep, ev)
	case *types.EpollCtlEvent:
		return e.handleEpollCtlExit(ep, ev)
	case *types.PollEvent:
		return e.handlePollExit(ep, ev)
	case *types.MemEvent:
		return e.handleMemExit(ep, ev)
	case *types.SleepEvent:
		return e.handleSleepExit(ep, ev)
	case *types.NullEvent:
		return e.handleNullExit(ep, ev)
	case *types.FcntlEvent:
		return e.handleFcntlExit(ep, ev)
	default:
		e.recyclePair(ep, "Dropped malformed enter event")
		return false
	}
}

func (e *eventLoop) handleOpenExit(ep *event.Pair, openEv *types.OpenEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed open exit event")
		return false
	}

	comm := types.StringValue(openEv.Comm[:])
	ep.Comm = comm
	if fd := int32(retEvent.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, types.StringValue(openEv.Filename[:]), openEv.Flags)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	} else {
		// Keep path information for failed opens so error scenarios remain observable.
		ep.File = file.NewPathname(openEv.Filename[:])
	}
	e.setCachedComm(openEv.Tid, comm)
	return true
}

func (e *eventLoop) handleNameExit(ep *event.Pair, nameEv *types.NameEvent) bool {
	ep.File = file.NewOldnameNewname(nameEv.Oldname[:], nameEv.Newname[:])
	ep.Comm = e.comm(nameEv.GetTid())
	return true
}

func (e *eventLoop) handlePathExit(ep *event.Pair, pathEv *types.PathEvent) bool {
	if pathEv.GetTraceId().Name() == sysEnterNameToHandleAtName {
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if !ok || retEv.Ret < 0 {
			ep.Recycle()
			return false
		}
		e.pendingHandleState().set(pathEv.GetTid(), types.StringValue(pathEv.Pathname[:]))
		ep.Recycle()
		return false
	}

	if ep.Is(types.SYS_ENTER_CREAT) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed creat exit event")
			return false
		}
		if fd := int32(retEvent.Ret); fd >= 0 {
			fdFile := file.NewFd(fd, types.StringValue(pathEv.Pathname[:]),
				syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC)
			e.fdState().set(fd, fdFile)
			ep.File = fdFile
		}
	} else {
		ep.File = file.NewPathname(pathEv.Pathname[:])
	}
	ep.Comm = e.comm(pathEv.GetTid())
	return true
}

// handleFdExit processes exit events for fd-based syscalls. It resolves the fd
// to a file, applies close/close_range state transitions, filters the pair, and
// handles dup/pidfd_getfd fd-transfer operations before finalising bytes.
func (e *eventLoop) handleFdExit(ep *event.Pair, fdEv *types.FdEvent) bool {
	fd := fdEv.Fd
	ep.File = e.fdState().resolve(fd, fdEv.Pid)
	e.applyFdCloseState(ep, fd, fdEv.Pid)
	ep.Comm = e.comm(fdEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	if ok := e.applyFdTransferOp(ep, fdEv); !ok {
		return false
	}
	return true
}

// applyFdCloseState updates fd-tracking state for close and close_range syscalls.
func (e *eventLoop) applyFdCloseState(ep *event.Pair, fd int32, pid uint32) {
	if ep.Is(types.SYS_ENTER_CLOSE) {
		e.fdState().delete(fd)
		e.fdState().deleteProcFdCache(fd, pid)
		return
	}
	if ep.Is(types.SYS_ENTER_CLOSE_RANGE) {
		// close_range provides (first, last), but fd_event only carries the first
		// argument, so we approximate by closing all tracked fds >= first.
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if ok && retEv.Ret == 0 {
			e.fdState().closeRangeFrom(fd)
			e.fdState().deleteProcFdCacheFrom(fd, pid)
		}
	}
}

// applyFdTransferOp handles dup/dup2 and pidfd_getfd fd-transfer operations.
// Returns false if the pair should be dropped due to a malformed event.
func (e *eventLoop) applyFdTransferOp(ep *event.Pair, fdEv *types.FdEvent) bool {
	if ep.Is(types.SYS_ENTER_DUP) || ep.Is(types.SYS_ENTER_DUP2) {
		fdFile, ok := ep.File.(*file.FdFile)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup source event")
			return false
		}
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup exit event")
			return false
		}
		e.registerDup(fdFile, int32(retEvent.Ret), 0)
	}
	if ep.Is(types.SYS_ENTER_PIDFD_GETFD) {
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed pidfd_getfd exit event")
			return false
		}
		if newFd := int32(retEv.Ret); newFd >= 0 {
			transferredFile := file.NewFdWithPid(newFd, fdEv.Pid)
			e.fdState().set(newFd, transferredFile)
			ep.File = transferredFile
		}
	}
	return true
}

func (e *eventLoop) handleDup3Exit(ep *event.Pair, dup3Ev *types.Dup3Event) bool {
	fd := int32(dup3Ev.Fd)
	ep.File = e.fdState().resolve(fd, dup3Ev.Pid)
	ep.Comm = e.comm(dup3Ev.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}

	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 source event")
		return false
	}
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 exit event")
		return false
	}
	e.registerDup(fdFile, int32(retEvent.Ret), dup3Ev.Flags&syscall.O_CLOEXEC)
	return true
}

func (e *eventLoop) handleOpenByHandleAtExit(ep *event.Pair, openByHandleEv *types.OpenByHandleAtEvent) bool {
	tid := openByHandleEv.GetTid()
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.pendingHandleState().delete(tid)
		e.recyclePair(ep, "Dropped malformed open_by_handle_at exit event")
		return false
	}

	fd := int32(retEvent.Ret)
	if fd < 0 {
		e.pendingHandleState().delete(tid)
		ep.Recycle()
		return false
	}

	if pathname, ok := e.pendingHandleState().consume(tid); ok {
		fdFile := file.NewFd(fd, pathname, openByHandleEv.Flags)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	} else {
		fdFile := file.NewFdWithPid(fd, openByHandleEv.Pid)
		if fdFile.Flags() == file.Flags(-1) {
			fdFile.SetFlags(openByHandleEv.Flags)
		}
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(tid)
	return true
}

func (e *eventLoop) handleSocketExit(ep *event.Pair, socketEv *types.SocketEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed socket exit event")
		return false
	}

	if fd := int32(retEvent.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, socketDescriptorName(socketEv.Family, socketEv.Type, socketEv.Protocol), -1)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(socketEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleSocketpairExit(ep *event.Pair, socketpairEv *types.SocketpairEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.SocketpairEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed socketpair exit event")
		return false
	}

	family := exitEv.Family
	typ := exitEv.Type
	protocol := exitEv.Protocol
	if family < 0 {
		family = socketpairEv.Family
	}
	if typ < 0 {
		typ = socketpairEv.Type
	}
	if protocol < 0 {
		protocol = socketpairEv.Protocol
	}

	if exitEv.Ret == 0 {
		if exitEv.Sv0 >= 0 {
			fdFile := file.NewFd(exitEv.Sv0, socketDescriptorName(family, typ, protocol), -1)
			e.fdState().set(exitEv.Sv0, fdFile)
			ep.File = fdFile
		}
		if exitEv.Sv1 >= 0 {
			fdFile := file.NewFd(exitEv.Sv1, socketDescriptorName(family, typ, protocol), -1)
			e.fdState().set(exitEv.Sv1, fdFile)
			if ep.File == nil {
				ep.File = fdFile
			}
		}
	}
	ep.Comm = e.comm(socketpairEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleAcceptExit(ep *event.Pair, acceptEv *types.AcceptEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.AcceptEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed accept exit event")
		return false
	}

	listening := e.fdState().resolve(acceptEv.Fd, acceptEv.Pid)
	if fd := int32(exitEv.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, acceptedSocketDescriptorName(listening), -1)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	} else {
		ep.File = listening
	}
	ep.Comm = e.comm(acceptEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func socketDescriptorName(family, typ, protocol int32) string {
	return fmt.Sprintf("socket:%d:%d:%d", family, typ, protocol)
}

func acceptedSocketDescriptorName(listening file.File) string {
	if listening == nil {
		return "socket:accepted"
	}
	name := listening.Name()
	if name == "" {
		return "socket:accepted"
	}
	return name
}

func (e *eventLoop) handlePipeExit(ep *event.Pair, pipeEv *types.PipeEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.PipeEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed pipe exit event")
		return false
	}

	flags := exitEv.Flags
	if flags == 0 {
		flags = pipeEv.Flags
	}
	if exitEv.Ret == 0 {
		if exitEv.Fd0 >= 0 {
			fdFile := file.NewFd(exitEv.Fd0, pipeDescriptorName(flags, exitEv.Fd0, exitEv.Fd1), flags)
			e.fdState().set(exitEv.Fd0, fdFile)
			ep.File = fdFile
		}
		if exitEv.Fd1 >= 0 {
			fdFile := file.NewFd(exitEv.Fd1, pipeDescriptorName(flags, exitEv.Fd0, exitEv.Fd1), flags)
			e.fdState().set(exitEv.Fd1, fdFile)
			if ep.File == nil {
				ep.File = fdFile
			}
		}
	}
	ep.Comm = e.comm(pipeEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleEventfdExit(ep *event.Pair, eventfdEv *types.EventfdEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.EventfdEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed eventfd exit event")
		return false
	}

	flags := exitEv.Flags
	if flags == 0 {
		flags = eventfdEv.Flags
	}
	if fd := int32(exitEv.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, eventfdDescriptorName(flags), flags)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(eventfdEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleEpollCtlExit(ep *event.Pair, epollCtlEv *types.EpollCtlEvent) bool {
	ep.File = e.fdState().resolve(epollCtlEv.Epfd, epollCtlEv.Pid)
	ep.Comm = e.comm(epollCtlEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handlePollExit(ep *event.Pair, pollEv *types.PollEvent) bool {
	ep.Comm = e.comm(pollEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleMemExit(ep *event.Pair, memEv *types.MemEvent) bool {
	ep.Comm = e.comm(memEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleSleepExit(ep *event.Pair, sleepEv *types.SleepEvent) bool {
	ep.Comm = e.comm(sleepEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func pipeDescriptorName(flags, fd0, fd1 int32) string {
	return fmt.Sprintf("pipe:%d:%d:%d", flags, fd0, fd1)
}

func eventfdDescriptorName(flags int32) string {
	return fmt.Sprintf("eventfd:%d", flags)
}

func (e *eventLoop) handleNullExit(ep *event.Pair, nullEv *types.NullEvent) bool {
	if ep.Is(types.SYS_ENTER_IO_URING_SETUP) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed io_uring_setup exit event")
			return false
		}
		if fd := int32(retEvent.Ret); fd >= 0 {
			fdFile := file.NewFdWithPid(fd, nullEv.Pid)
			e.fdState().set(fd, fdFile)
			ep.File = fdFile
		}
	}
	if ep.Is(types.SYS_ENTER_GETCWD) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed getcwd exit event")
			return false
		}
		if retEvent.Ret > 0 {
			cwd, err := os.Readlink(procTidPathPrefix(nullEv.GetTid()) + "/cwd")
			switch {
			case err == nil:
				ep.File = file.NewPathname([]byte(cwd))
			case !isTransientProcError(err):
				e.notifyWarning(fmt.Sprintf("failed to resolve cwd for tid %d: %v", nullEv.GetTid(), err))
			}
		}
	}
	ep.Comm = e.comm(nullEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleFcntlExit(ep *event.Pair, fcntlEv *types.FcntlEvent) bool {
	ep.Comm = e.comm(fcntlEv.GetTid())
	fd := int32(fcntlEv.Fd)
	ep.File = e.fdState().resolve(fd, fcntlEv.Pid)
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}

	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl exit event")
		return false
	}
	// Syscall returned a negative errno, nothing was changed with the fd.
	if retEvent.Ret < 0 {
		return true
	}

	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl file event")
		return false
	}

	// See fcntl(2) for implementation details
	switch fcntlEv.Cmd {
	case syscall.F_SETFL:
		const canChange = syscall.O_APPEND | syscall.O_ASYNC | syscall.O_DIRECT | syscall.O_NOATIME | syscall.O_NONBLOCK
		fdFile.SetFlags(int32(fcntlEv.Arg) & int32(canChange))
		ep.File = fdFile
		e.fdState().set(fd, fdFile)
	case syscall.F_DUPFD:
		e.registerDup(fdFile, int32(retEvent.Ret), 0)
	case syscall.F_DUPFD_CLOEXEC:
		e.registerDup(fdFile, int32(retEvent.Ret), syscall.O_CLOEXEC)
	}
	return true
}

func (e *eventLoop) registerDup(fdFile *file.FdFile, newFd int32, extraFlags int32) {
	if newFd < 0 {
		return
	}
	duppedFdFile := fdFile.Dup(newFd)
	if extraFlags != 0 {
		duppedFdFile.AddFlags(extraFlags)
	}
	e.fdState().set(newFd, duppedFdFile)
}

// recyclePair notifies about the problem described by warning, then returns ep
// to the pool. It is a convenience helper used throughout the exit handlers to
// keep the error path concise.
func (e *eventLoop) recyclePair(ep *event.Pair, warning string) {
	e.notifyWarning(warning)
	ep.Recycle()
}

func applyRetBytes(ep *event.Pair) {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		return
	}
	ep.Bytes = bytesFromRet(retEv)
}

func applyAddressSpaceBytes(ep *event.Pair) {
	if ep == nil {
		return
	}
	memEv, ok := ep.EnterEv.(*types.MemEvent)
	if !ok {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret < 0 {
		return
	}
	ep.AddressSpaceBytes = addressSpaceBytesFromMem(memEv)
}

func applyRequestedSleepNs(ep *event.Pair) {
	if ep == nil {
		return
	}
	sleepEv, ok := ep.EnterEv.(*types.SleepEvent)
	if !ok {
		return
	}
	ep.RequestedSleepNs = sleepEv.RequestedNs
}

// dropMalformedRawEvent records a warning when a raw BPF event cannot be
// decoded, keeping the error visible without crashing the event loop.
func (e *eventLoop) dropMalformedRawEvent(evType types.EventType, raw []byte) {
	e.notifyWarning(fmt.Sprintf("Dropped malformed raw event type %d (len=%d)", evType, len(raw)))
}

// bytesFromRet extracts the number of bytes transferred from a RetEvent.
// Returns 0 for nil events, errors (Ret <= 0), or unclassified syscalls.
func bytesFromRet(retEv *types.RetEvent) uint64 {
	if retEv == nil || retEv.Ret <= 0 {
		return 0
	}
	switch retEv.RetType {
	case types.READ_CLASSIFIED, types.WRITE_CLASSIFIED, types.TRANSFER_CLASSIFIED:
		return uint64(retEv.Ret)
	default:
		return 0
	}
}

func addressSpaceBytesFromMem(memEv *types.MemEvent) uint64 {
	if memEv == nil {
		return 0
	}
	switch memEv.GetTraceId() {
	case types.SYS_ENTER_MUNMAP:
		return memEv.Length
	case types.SYS_ENTER_MREMAP:
		if memEv.Length > memEv.Length2 {
			return memEv.Length
		}
		return memEv.Length2
	default:
		return 0
	}
}
