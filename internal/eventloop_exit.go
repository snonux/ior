package internal

import (
	"fmt"
	"os"
	"syscall"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

func (e *eventLoop) initRuntimeEventKinds() {
	if e.exitHandlers == nil {
		e.exitHandlers = make(map[types.EventType]runtimeExitHandler)
	}
	if len(e.exitHandlers) != 0 {
		return
	}
	for _, kind := range runtimeEventKinds() {
		e.exitHandlers[kind.enterEventType] = kind.exit
	}
}

// handleTracepointExit routes a completed enter/exit pair to the runtime
// handler registered for the enter event kind.
func (e *eventLoop) handleTracepointExit(ep *event.Pair) bool {
	e.initRuntimeEventKinds()
	eventType, ok := eventTypeForRuntimeEvent(ep.EnterEv)
	if !ok {
		e.recyclePair(ep, "Dropped malformed enter event")
		return false
	}
	handler, ok := e.exitHandlers[eventType]
	if !ok {
		e.recyclePair(ep, "Dropped malformed enter event")
		return false
	}
	return handler(e, ep)
}

func eventTypeForRuntimeEvent(ev event.Event) (types.EventType, bool) {
	typed, ok := ev.(interface{ GetEventType() types.EventType })
	if !ok {
		return 0, false
	}
	return typed.GetEventType(), true
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

func (e *eventLoop) handleExecExit(ep *event.Pair, execEv *types.ExecEvent) bool {
	if _, ok := ep.ExitEv.(*types.RetEvent); !ok {
		e.recyclePair(ep, "Dropped malformed exec exit event")
		return false
	}
	comm := types.StringValue(execEv.Comm[:])
	ep.Comm = comm
	ep.File = file.NewPathname(execEv.Filename[:])
	e.setCachedComm(execEv.Tid, comm)
	return e.finishPair(ep)
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
			// creat(pathname, mode) == open(pathname, O_CREAT|O_WRONLY|O_TRUNC,
			// mode): on success it returns a new fd, so register the fd->path
			// mapping just like handleOpenExit does for open/openat/openat2.
			fdFile := file.NewFd(fd, types.StringValue(pathEv.Pathname[:]),
				syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC)
			e.fdState().set(fd, fdFile)
			ep.File = fdFile
		} else {
			// Failed creat (-1): keep the path so error scenarios stay
			// observable, mirroring handleOpenExit's failed-open branch.
			ep.File = file.NewPathname(pathEv.Pathname[:])
		}
	} else {
		ep.File = file.NewPathname(pathEv.Pathname[:])
	}
	ep.Comm = e.comm(pathEv.GetTid())
	return true
}

// handleFdExit processes exit events for fd-based syscalls. It resolves the fd
// to a file, applies the close state transition, filters the pair, and handles
// dup/pidfd_getfd fd-transfer operations before finalising bytes. close_range is
// not handled here: it carries (first, last, flags) and is routed through
// handleTwoFdExit so the upper bound and flags are honoured.
func (e *eventLoop) handleFdExit(ep *event.Pair, fdEv *types.FdEvent) bool {
	fd := fdEv.Fd
	ep.File = e.fdState().resolve(fd, fdEv.Pid)
	e.applyFdCloseState(ep, fd, fdEv.Pid)
	ep.Comm = e.comm(fdEv.GetTid())
	if !e.finishPair(ep) {
		return false
	}
	if ok := e.applyFdTransferOp(ep, fdEv); !ok {
		return false
	}
	return true
}

// applyFdCloseState updates fd-tracking state for the close syscall. The fd is
// deregistered only on a SUCCESSFUL close (ret == 0): per close(2), a failed
// close — most importantly EBADF, "fd isn't a valid open file descriptor" —
// did not release any descriptor we are tracking, so evicting the mapping there
// would drop a still-valid fd->path entry and let a later genuine close (or a
// reuse of the number) resolve against a stale/empty state. This mirrors the
// ret == 0 gate already applied by applyCloseRangeState for close_range.
func (e *eventLoop) applyFdCloseState(ep *event.Pair, fd int32, pid uint32) {
	if !ep.Is(types.SYS_ENTER_CLOSE) {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret != 0 {
		return
	}
	e.fdState().delete(fd)
	e.fdState().deleteProcFdCache(fd, pid)
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
	if !e.finishPair(ep) {
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
	return e.finishPair(ep)
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
	return e.finishPair(ep)
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
	return e.finishPair(ep)
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
	return e.finishPair(ep)
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
		fdFile := file.NewFd(fd, eventfdDescriptorName(eventfdEv.GetTraceId(), flags), flags)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(eventfdEv.GetTid())
	return e.finishPair(ep)
}

func (e *eventLoop) handleEpollCtlExit(ep *event.Pair, epollCtlEv *types.EpollCtlEvent) bool {
	// File resolves to the epoll instance (epfd); the decoded op/target-fd/events
	// are surfaced separately via ep.Epoll so consumers can see which descriptor
	// was registered and the operation performed.
	ep.File = e.fdState().resolve(epollCtlEv.Epfd, epollCtlEv.Pid)
	ep.Epoll = event.EpollCtl{
		Op:       epollCtlEv.Op,
		TargetFD: epollCtlEv.Fd,
		Events:   epollCtlEv.Events,
	}
	ep.HasEpoll = true
	return e.finishPairForTid(ep, epollCtlEv.GetTid())
}

func (e *eventLoop) handlePollExit(ep *event.Pair, pollEv *types.PollEvent) bool {
	return e.finishPairForTid(ep, pollEv.GetTid())
}

func (e *eventLoop) handleTwoFdExit(ep *event.Pair, twoFdEv *types.TwoFdEvent) bool {
	ep.File = e.fdState().resolve(twoFdEv.FdA, twoFdEv.Pid)
	if ep.Is(types.SYS_ENTER_CLOSE_RANGE) {
		e.applyCloseRangeState(ep, twoFdEv)
	}
	return e.finishPairForTid(ep, twoFdEv.GetTid())
}

// closeRangeCloexec mirrors CLOSE_RANGE_CLOEXEC from <linux/close_range.h>: when
// set, close_range only marks the descriptors close-on-exec instead of closing
// them, so the fds stay open and must remain tracked.
const closeRangeCloexec = 1 << 2

// applyCloseRangeState evicts the fds closed by a successful close_range. The
// enter event carries (first, last, flags) in fd_a/fd_b/extra. fd_b is an __s32
// view of the unsigned "last" argument, so a negative value (e.g. ~0U meaning
// "close everything from first up") is treated as having no upper bound.
func (e *eventLoop) applyCloseRangeState(ep *event.Pair, ev *types.TwoFdEvent) {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret != 0 {
		return
	}
	if ev.Extra&closeRangeCloexec != 0 {
		return
	}
	e.fdState().closeRange(ev.FdA, ev.FdB)
	e.fdState().deleteProcFdCacheRange(ev.FdA, ev.FdB, ev.Pid)
}

func (e *eventLoop) handleMemExit(ep *event.Pair, memEv *types.MemEvent) bool {
	return e.finishPairForTid(ep, memEv.GetTid())
}

func (e *eventLoop) handleSleepExit(ep *event.Pair, sleepEv *types.SleepEvent) bool {
	return e.finishPairForTid(ep, sleepEv.GetTid())
}

func (e *eventLoop) handleKeyctlExit(ep *event.Pair, keyctlEv *types.KeyctlEvent) bool {
	return e.finishPairForTid(ep, keyctlEv.GetTid())
}

func (e *eventLoop) handlePtraceExit(ep *event.Pair, ptraceEv *types.PtraceEvent) bool {
	return e.finishPairForTid(ep, ptraceEv.GetTid())
}

func (e *eventLoop) handlePerfOpenExit(ep *event.Pair, perfOpenEv *types.PerfOpenEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed perf_event_open exit event")
		return false
	}

	if fd := int32(retEvent.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, perfDescriptorName(perfOpenEv), -1)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(perfOpenEv.GetTid())
	return e.finishPair(ep)
}

func pipeDescriptorName(flags, fd0, fd1 int32) string {
	return fmt.Sprintf("pipe:%d:%d:%d", flags, fd0, fd1)
}

func eventfdDescriptorName(traceID types.TraceId, flags int32) string {
	switch traceID {
	case types.SYS_ENTER_EPOLL_CREATE, types.SYS_ENTER_EPOLL_CREATE1:
		return fmt.Sprintf("epollfd:%d", flags)
	case types.SYS_ENTER_INOTIFY_INIT, types.SYS_ENTER_INOTIFY_INIT1:
		return fmt.Sprintf("inotifyfd:%d", flags)
	case types.SYS_ENTER_FANOTIFY_INIT:
		return fmt.Sprintf("fanotifyfd:%d", flags)
	case types.SYS_ENTER_LANDLOCK_CREATE_RULESET:
		return fmt.Sprintf("landlockfd:%d", flags)
	case types.SYS_ENTER_FSOPEN:
		return fmt.Sprintf("fsopenfd:%d", flags)
	case types.SYS_ENTER_MEMFD_CREATE:
		return fmt.Sprintf("memfd:%d", flags)
	case types.SYS_ENTER_MEMFD_SECRET:
		return fmt.Sprintf("memfd-secret:%d", flags)
	case types.SYS_ENTER_USERFAULTFD:
		return fmt.Sprintf("userfaultfd:%d", flags)
	case types.SYS_ENTER_SIGNALFD, types.SYS_ENTER_SIGNALFD4:
		return fmt.Sprintf("signalfd:%d", flags)
	case types.SYS_ENTER_TIMERFD_CREATE:
		return fmt.Sprintf("timerfd:%d", flags)
	case types.SYS_ENTER_PIDFD_OPEN:
		return fmt.Sprintf("pidfd:%d", flags)
	default:
		return fmt.Sprintf("eventfd:%d", flags)
	}
}

func perfDescriptorName(perfOpenEv *types.PerfOpenEvent) string {
	return fmt.Sprintf(
		"perf:%d:%d:%d:%d:%d",
		perfOpenEv.AttrType,
		perfOpenEv.Config,
		perfOpenEv.TargetPid,
		perfOpenEv.Cpu,
		perfOpenEv.GroupFd,
	)
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
	return e.finishPair(ep)
}

func (e *eventLoop) handleFcntlExit(ep *event.Pair, fcntlEv *types.FcntlEvent) bool {
	ep.Comm = e.comm(fcntlEv.GetTid())
	fd := int32(fcntlEv.Fd)
	ep.File = e.fdState().resolve(fd, fcntlEv.Pid)
	if !e.finishPair(ep) {
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

func (e *eventLoop) finishPairForTid(ep *event.Pair, tid uint32) bool {
	ep.Comm = e.comm(tid)
	return e.finishPair(ep)
}

func (e *eventLoop) finishPair(ep *event.Pair) bool {
	if e.Filter().MatchPair(ep) {
		return true
	}
	ep.Recycle()
	return false
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
