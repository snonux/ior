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

func (e *eventLoop) handleFdExit(ep *event.Pair, fdEv *types.FdEvent) bool {
	fd := fdEv.Fd
	ep.File = e.fdState().resolve(fd, fdEv.Pid)
	if ep.Is(types.SYS_ENTER_CLOSE) {
		e.fdState().delete(fd)
		e.fdState().deleteProcFdCache(fd, fdEv.Pid)
	}
	if ep.Is(types.SYS_ENTER_CLOSE_RANGE) {
		// close_range provides (first, last), but fd_event only carries the first
		// argument, so we approximate by closing all tracked fds >= first.
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if ok && retEv.Ret == 0 {
			e.fdState().closeRangeFrom(fd)
			e.fdState().deleteProcFdCacheFrom(fd, fdEv.Pid)
		}
	}
	ep.Comm = e.comm(fdEv.GetTid())
	if !e.Filter().MatchPair(ep) {
		ep.Recycle()
		return false
	}

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
		// Duplicating fd
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
	if retEv, ok := ep.ExitEv.(*types.RetEvent); ok {
		ep.Bytes = bytesFromRet(retEv)
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

func (e *eventLoop) recyclePair(ep *event.Pair, warning string) {
	e.notifyWarning(warning)
	ep.Recycle()
}

func (e *eventLoop) notifyWarning(message string) {
	if e.warningCb == nil || message == "" {
		return
	}
	e.warningCb(message)
}

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
