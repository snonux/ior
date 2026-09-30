package internal

import (
	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

type runtimeDecodedEvent interface {
	event.EventLifecycle
}

type runtimeEventDecoder func(raw []byte) runtimeDecodedEvent
type runtimeExitHandler func(e *eventLoop, ep *event.Pair) bool
type runtimeEnterFilter func(filter globalfilter.Filter, ev event.Event) bool

// runtimeControlHandler consumes a control event: a ring-buffer record that
// carries state for the event loop instead of a syscall to report. The handler
// owns the event and must recycle it. ch is the completed-pair channel of the
// raw record being processed: a control record is never a row itself, but it
// may complete at most one pending pair (the exec record under -tid, see
// eventLoop.completeUntracedExec) and send it there like an exit record would.
type runtimeControlHandler func(e *eventLoop, ev runtimeDecodedEvent, ch chan<- *event.Pair)

type runtimeEventKind struct {
	enterEventType types.EventType
	exit           runtimeExitHandler
}

type rawEventDirection uint8

const (
	rawEnterEvent rawEventDirection = iota
	rawExitEvent
	// rawControlEvent is neither side of a syscall pair. It updates event-loop
	// state and is never emitted as a row.
	rawControlEvent
)

type rawRuntimeEvent struct {
	eventType types.EventType
	direction rawEventDirection
	decode    runtimeEventDecoder
	filter    runtimeEnterFilter
	control   runtimeControlHandler
}

type eventPtr[T any] interface {
	*T
	event.Event
}

type decodedEventPtr[T any] interface {
	*T
	runtimeDecodedEvent
}

func rawDecoder[T any, P decodedEventPtr[T]](decode func([]byte) P) runtimeEventDecoder {
	return func(raw []byte) runtimeDecodedEvent {
		ev := decode(raw)
		if ev == nil {
			return nil
		}
		return ev
	}
}

// typedRuntimeControl adapts a control handler that only updates event-loop
// state and never completes a pair.
func typedRuntimeControl[T any, P decodedEventPtr[T]](handle func(*eventLoop, P)) runtimeControlHandler {
	return typedRuntimePairControl(func(e *eventLoop, ev P, _ chan<- *event.Pair) { handle(e, ev) })
}

// typedRuntimePairControl adapts a control handler that may complete a pending
// pair and send it on ch. A record of the wrong type is reported and recycled.
func typedRuntimePairControl[T any, P decodedEventPtr[T]](handle func(*eventLoop, P, chan<- *event.Pair)) runtimeControlHandler {
	return func(e *eventLoop, ev runtimeDecodedEvent, ch chan<- *event.Pair) {
		typed, ok := ev.(P)
		if !ok {
			e.notifyWarning("Dropped malformed control event")
			ev.Recycle()
			return
		}
		handle(e, typed, ch)
	}
}

func typedRuntimeExit[T any, P eventPtr[T]](handle func(*eventLoop, *event.Pair, P) bool) runtimeExitHandler {
	return func(e *eventLoop, ep *event.Pair) bool {
		ev, ok := ep.EnterEv.(P)
		if !ok {
			e.recyclePair(ep, "Dropped malformed enter event")
			return false
		}
		return handle(e, ep, ev)
	}
}

func runtimeEventKinds() []runtimeEventKind {
	return []runtimeEventKind{
		{enterEventType: types.ENTER_OPEN_EVENT, exit: typedRuntimeExit((*eventLoop).handleOpenExit)},
		{enterEventType: types.ENTER_EXEC_EVENT, exit: typedRuntimeExit((*eventLoop).handleExecExit)},
		{enterEventType: types.ENTER_NAME_EVENT, exit: typedRuntimeExit((*eventLoop).handleNameExit)},
		{enterEventType: types.ENTER_PATH_EVENT, exit: typedRuntimeExit((*eventLoop).handlePathExit)},
		{enterEventType: types.ENTER_FD_PATH_EVENT, exit: typedRuntimeExit((*eventLoop).handleFdPathExit)},
		{enterEventType: types.ENTER_FD_EVENT, exit: typedRuntimeExit((*eventLoop).handleFdExit)},
		{enterEventType: types.ENTER_FD_SIZE_EVENT, exit: typedRuntimeExit((*eventLoop).handleFdExit)},
		{enterEventType: types.ENTER_DUP3_EVENT, exit: typedRuntimeExit((*eventLoop).handleDup3Exit)},
		{enterEventType: types.ENTER_OPEN_BY_HANDLE_AT_EVENT, exit: typedRuntimeExit((*eventLoop).handleOpenByHandleAtExit)},
		{enterEventType: types.ENTER_SOCKET_EVENT, exit: typedRuntimeExit((*eventLoop).handleSocketExit)},
		{enterEventType: types.ENTER_SOCKETPAIR_EVENT, exit: typedRuntimeExit((*eventLoop).handleSocketpairExit)},
		{enterEventType: types.ENTER_ACCEPT_EVENT, exit: typedRuntimeExit((*eventLoop).handleAcceptExit)},
		{enterEventType: types.ENTER_PIPE_EVENT, exit: typedRuntimeExit((*eventLoop).handlePipeExit)},
		{enterEventType: types.ENTER_EVENTFD_EVENT, exit: typedRuntimeExit((*eventLoop).handleEventfdExit)},
		{enterEventType: types.ENTER_EVENTFD_NAME_EVENT, exit: typedRuntimeExit((*eventLoop).handleEventfdExit)},
		{enterEventType: types.ENTER_EPOLL_CTL_EVENT, exit: typedRuntimeExit((*eventLoop).handleEpollCtlExit)},
		{enterEventType: types.ENTER_POLL_EVENT, exit: typedRuntimeExit((*eventLoop).handlePollExit)},
		{enterEventType: types.ENTER_TWO_FD_EVENT, exit: typedRuntimeExit((*eventLoop).handleTwoFdExit)},
		{enterEventType: types.ENTER_TWO_FD_NAMES_EVENT, exit: typedRuntimeExit((*eventLoop).handleTwoFdExit)},
		{enterEventType: types.ENTER_MEM_EVENT, exit: typedRuntimeExit((*eventLoop).handleMemExit)},
		{enterEventType: types.ENTER_MMAP_EVENT, exit: typedRuntimeExit((*eventLoop).handleMmapExit)},
		{enterEventType: types.ENTER_SLEEP_EVENT, exit: typedRuntimeExit((*eventLoop).handleSleepExit)},
		{enterEventType: types.ENTER_KEYCTL_EVENT, exit: typedRuntimeExit((*eventLoop).handleKeyctlExit)},
		{enterEventType: types.ENTER_PTRACE_EVENT, exit: typedRuntimeExit((*eventLoop).handlePtraceExit)},
		{enterEventType: types.ENTER_PERF_OPEN_EVENT, exit: typedRuntimeExit((*eventLoop).handlePerfOpenExit)},
		{enterEventType: types.ENTER_BPF_EVENT, exit: typedRuntimeExit((*eventLoop).handleBpfExit)},
		{enterEventType: types.ENTER_NULL_EVENT, exit: typedRuntimeExit((*eventLoop).handleNullExit)},
		{enterEventType: types.ENTER_FCNTL_EVENT, exit: typedRuntimeExit((*eventLoop).handleFcntlExit)},
	}
}

func rawRuntimeEvents() []rawRuntimeEvent {
	return []rawRuntimeEvent{
		enterRaw(types.ENTER_OPEN_EVENT, rawDecoder[types.OpenEvent](types.NewOpenEventFast), matchRawOpenEvent),
		exitRaw(types.EXIT_OPEN_EVENT, rawDecoder[types.RetEvent](types.NewRetEventFast)),
		enterRaw(types.ENTER_FD_EVENT, rawDecoder[types.FdEvent](types.NewFdEventFast), nil),
		enterRaw(types.ENTER_FD_SIZE_EVENT, decodeFdSizeEvent, nil),
		exitRaw(types.EXIT_FD_EVENT, rawDecoder[types.FdEvent](types.NewFdEventFast)),
		enterRaw(types.ENTER_NULL_EVENT, rawDecoder[types.NullEvent](types.NewNullEventFast), nil),
		exitRaw(types.EXIT_NULL_EVENT, rawDecoder[types.NullEvent](types.NewNullEventFast)),
		exitRaw(types.EXIT_RET_EVENT, rawDecoder[types.RetEvent](types.NewRetEventFast)),
		enterRaw(types.ENTER_NAME_EVENT, rawDecoder[types.NameEvent](types.NewNameEventFast), matchRawNameEvent),
		enterRaw(types.ENTER_PATH_EVENT, rawDecoder[types.PathEvent](types.NewPathEventFast), matchRawPathEvent),
		// The target may need dirfd resolution; filter the completed pair.
		enterRaw(types.ENTER_FD_PATH_EVENT, rawDecoder[types.FdPathEvent](types.NewFdPathEventFast), nil),
		enterRaw(types.ENTER_FCNTL_EVENT, rawDecoder[types.FcntlEvent](types.NewFcntlEventFast), nil),
		enterRaw(types.ENTER_OPEN_BY_HANDLE_AT_EVENT, rawDecoder[types.OpenByHandleAtEvent](types.NewOpenByHandleAtEventFast), nil),
		enterRaw(types.ENTER_DUP3_EVENT, rawDecoder[types.Dup3Event](types.NewDup3EventFast), nil),
		enterRaw(types.ENTER_SOCKET_EVENT, rawDecoder[types.SocketEvent](types.NewSocketEventFast), nil),
		enterRaw(types.ENTER_SOCKETPAIR_EVENT, rawDecoder[types.SocketpairEvent](types.NewSocketpairEventFast), nil),
		exitRaw(types.EXIT_SOCKETPAIR_EVENT, rawDecoder[types.SocketpairEvent](types.NewSocketpairEventFast)),
		enterRaw(types.ENTER_ACCEPT_EVENT, rawDecoder[types.AcceptEvent](types.NewAcceptEventFast), nil),
		exitRaw(types.EXIT_ACCEPT_EVENT, rawDecoder[types.AcceptEvent](types.NewAcceptEventFast)),
		enterRaw(types.ENTER_PIPE_EVENT, rawDecoder[types.PipeEvent](types.NewPipeEventFast), nil),
		exitRaw(types.EXIT_PIPE_EVENT, rawDecoder[types.PipeEvent](types.NewPipeEventFast)),
		enterRaw(types.ENTER_EVENTFD_EVENT, rawDecoder[types.EventfdEvent](types.NewEventfdEventFast), nil),
		enterRaw(types.ENTER_EVENTFD_NAME_EVENT, decodeEventfdNameEvent, nil),
		exitRaw(types.EXIT_EVENTFD_EVENT, rawDecoder[types.EventfdEvent](types.NewEventfdEventFast)),
		enterRaw(types.ENTER_EPOLL_CTL_EVENT, rawDecoder[types.EpollCtlEvent](types.NewEpollCtlEventFast), nil),
		enterRaw(types.ENTER_POLL_EVENT, rawDecoder[types.PollEvent](types.NewPollEventFast), nil),
		enterRaw(types.ENTER_TWO_FD_EVENT, rawDecoder[types.TwoFdEvent](types.NewTwoFdEventFast), nil),
		enterRaw(types.ENTER_TWO_FD_NAMES_EVENT, decodeTwoFdNamesEvent, nil),
		enterRaw(types.ENTER_MEM_EVENT, rawDecoder[types.MemEvent](types.NewMemEventFast), nil),
		enterRaw(types.ENTER_MMAP_EVENT, rawDecoder[types.MmapEvent](types.NewMmapEventFast), nil),
		enterRaw(types.ENTER_SLEEP_EVENT, rawDecoder[types.SleepEvent](types.NewSleepEventFast), nil),
		enterRaw(types.ENTER_EXEC_EVENT, rawDecoder[types.ExecEvent](types.NewExecEventFast), nil),
		enterRaw(types.ENTER_KEYCTL_EVENT, rawDecoder[types.KeyctlEvent](types.NewKeyctlEventFast), nil),
		enterRaw(types.ENTER_PTRACE_EVENT, rawDecoder[types.PtraceEvent](types.NewPtraceEventFast), nil),
		enterRaw(types.ENTER_PERF_OPEN_EVENT, rawDecoder[types.PerfOpenEvent](types.NewPerfOpenEventFast), nil),
		enterRaw(types.ENTER_BPF_EVENT, rawDecoder[types.BpfEvent](types.NewBpfEvent), nil),
		controlRaw(types.PROCESS_EXEC_EVENT, rawDecoder[types.ProcessExecEvent](types.NewProcessExecEventFast),
			typedRuntimePairControl((*eventLoop).handleProcessExecEvent)),
		// sched:sched_process_exit fires for every exiting task. Every exit
		// drops that thread's cached comm, pending pairs and parked
		// name_to_handle_at path; the fdTracker
		// evicts the process's (pid, fd) entries only when the record marks
		// the exit that ends the thread group (group_dead), or when the flag
		// is unknown because the record uses the legacy pre-group_dead layout
		// - instead of holding them until LRU eviction
		// (internal/eventloop_processexit.go).
		controlRaw(types.PROCESS_EXIT_EVENT, rawDecoder[types.ProcessExitEvent](types.NewProcessExitEventFast),
			typedRuntimeControl((*eventLoop).handleProcessExitEvent)),
		// task:task_newtask fires for every created task (process or thread)
		// and seeds its inherited comm (provisionally: the task may rename
		// itself) before its first syscall, retiring the state a dead previous
		// owner of a recycled tid left behind (internal/eventloop_newtask.go).
		controlRaw(types.TASK_NEWTASK_EVENT, rawDecoder[types.TaskNewtaskEvent](types.NewTaskNewtaskEventFast),
			typedRuntimeControl((*eventLoop).handleTaskNewtaskEvent)),
		// The open-name fixup carries only the pending enter's identity and the
		// filename re-read at sys_exit once the kernel had faulted the page in.
		// Its dedicated decoder keeps the compact control record separate from
		// the much larger open syscall payload.
		controlRaw(types.OPEN_NAME_FIXUP_EVENT, rawDecoder[types.OpenNameFixupEvent](types.NewOpenNameFixupEventFast),
			typedRuntimeControl((*eventLoop).handleOpenNameFixupEvent)),
	}
}

// The new wire kinds retain the established userspace event types after
// decoding, including fields needed by older IOR_BPF_OBJECT payloads. This
// keeps filtering, descriptor state and output on their existing paths.
func decodeFdSizeEvent(raw []byte) runtimeDecodedEvent {
	ev := types.NewFdSizeEventFast(raw)
	if ev == nil {
		return nil
	}
	out := &types.FdEvent{EventType: ev.EventType, TraceId: ev.TraceId, Time: ev.Time,
		Pid: ev.Pid, Tid: ev.Tid, Fd: ev.Fd, Flags: ev.Flags, Size: ev.Size,
		SizeValid: ev.SizeValid, SchemaVersion: ev.SchemaVersion}
	ev.Recycle()
	return out
}

func decodeEventfdNameEvent(raw []byte) runtimeDecodedEvent {
	ev := types.NewEventfdNameEventFast(raw)
	if ev == nil {
		return nil
	}
	out := &types.EventfdEvent{EventType: ev.EventType, TraceId: ev.TraceId, Time: ev.Time,
		Pid: ev.Pid, Tid: ev.Tid, Flags: ev.Flags, Ret: ev.Ret, Fd: ev.Fd,
		Filename: ev.Filename, FilenameStatus: ev.FilenameStatus, SchemaVersion: ev.SchemaVersion}
	ev.Recycle()
	return out
}

func decodeTwoFdNamesEvent(raw []byte) runtimeDecodedEvent {
	ev := types.NewTwoFdNamesEventFast(raw)
	if ev == nil {
		return nil
	}
	out := &types.TwoFdEvent{EventType: ev.EventType, TraceId: ev.TraceId, Time: ev.Time,
		Pid: ev.Pid, Tid: ev.Tid, FdA: ev.FdA, FdB: ev.FdB, Extra: ev.Extra,
		Oldname: ev.Oldname, Newname: ev.Newname, OldnameStatus: ev.OldnameStatus,
		NewnameStatus: ev.NewnameStatus, SchemaVersion: ev.SchemaVersion}
	ev.Recycle()
	return out
}

func enterRaw(eventType types.EventType, decode runtimeEventDecoder, filter runtimeEnterFilter) rawRuntimeEvent {
	return rawRuntimeEvent{eventType: eventType, direction: rawEnterEvent, decode: decode, filter: filter}
}

func exitRaw(eventType types.EventType, decode runtimeEventDecoder) rawRuntimeEvent {
	return rawRuntimeEvent{eventType: eventType, direction: rawExitEvent, decode: decode}
}

func controlRaw(eventType types.EventType, decode runtimeEventDecoder, control runtimeControlHandler) rawRuntimeEvent {
	return rawRuntimeEvent{eventType: eventType, direction: rawControlEvent, decode: decode, control: control}
}

// matchRawOpenEvent is the enter-side gate for the open kinds. It normally
// applies the two dimensions an open payload can answer on its own, comm and
// path.
//
// The exception is an open whose payload filename is empty, i.e. one whose
// sys_enter bpf_probe_read_user_str faulted (see handleOpenNameFixupEvent). Its
// real path is not knowable *here* - it arrives a moment later as a fixup
// control record - so judging the path dimension now would answer it with "no
// name, no match" and drop the event before the recovery could ever be applied.
// That is precisely the failure this whole mechanism exists to remove: under
// `-path X` those opens were silently missing, and with them the fd-table entry
// that gives every later read/write/close on the descriptor its filename.
//
// So the path dimension alone is *deferred*, not waived. The comm dimension is
// still applied here, because the payload comm is always present. The deferred
// event is filtered at the exit checkpoint instead - handleOpenExit ends in the
// full finishPair, which applies every dimension including the file one, and by
// then the fixup has landed. Nothing can leak past filtering: if the name is
// never recovered (a still-failing read, or a fixup lost to ring-buffer
// backpressure) the pair reaches finishPair with an empty file name, which no
// non-empty -path pattern matches, so the row is dropped there exactly as it
// used to be dropped here.
func matchRawOpenEvent(filter globalfilter.Filter, ev event.Event) bool {
	openEv, ok := ev.(*types.OpenEvent)
	if !ok {
		return false
	}
	// A typed-nil *OpenEvent satisfies the assertion above, so the nil check
	// has to happen here rather than being left to the Match* helpers: reading
	// Filename[0] off it would panic. The sibling gates get this for free by
	// delegating straight to a helper that opens with a nil check; this one
	// dereferences first to decide which dimension set applies, so it has to
	// do the check itself.
	if openEv == nil {
		return filter.MatchOpenEventComm(openEv)
	}
	filename := types.StringValue(openEv.Filename[:])
	if openEv.FilenameStatus == types.PATH_READ_FAILED {
		// A failed non-NULL read may still be repaired by the exit fixup, so its
		// path dimension remains deferred even though the current buffer is
		// empty. NULL is different: it never gets a fixup and is matched as the
		// empty value below.
		return filter.MatchOpenEventComm(openEv)
	}
	if capturedPathNeedsDeferredResolution(openEv.Dirfd, filename, openEv.FilenameStatus,
		openEventAllowsEmptyPath(openEv, true)) {
		// The exit handler owns fd-table lookup and successful-return checks.
		// Comm is always present and still applies here.
		return filter.MatchOpenEventComm(openEv)
	}
	return filter.MatchOpenEvent(openEv)
}

// matchRawNameEvent is the enter-side gate for the rename/link kinds. A name
// whose sys_enter read faulted (PATH_READ_FAILED) arrives empty and is
// recovered by a fixup record at sys_exit, exactly like a faulted open name
// (see matchRawOpenEvent), so its path dimension is deferred to the exit
// checkpoint, where handleNameExit ends in finishPairForTid and every
// dimension is applied against the recovered names. Judging the empty name now
// would drop the row before the fixup could ever land.
func matchRawNameEvent(filter globalfilter.Filter, ev event.Event) bool {
	nameEv, ok := ev.(*types.NameEvent)
	if !ok || nameEv == nil {
		return false
	}
	if nameEv.OldnameStatus == types.PATH_READ_FAILED || nameEv.NewnameStatus == types.PATH_READ_FAILED {
		return true
	}
	if capturedPathNeedsDeferredResolution(nameEv.Olddirfd, types.StringValue(nameEv.Oldname[:]),
		nameEv.OldnameStatus, nameEventAllowsEmptyPath(nameEv, true, true)) ||
		capturedPathNeedsDeferredResolution(nameEv.Newdirfd, types.StringValue(nameEv.Newname[:]),
			nameEv.NewnameStatus, nameEventAllowsEmptyPath(nameEv, false, true)) {
		return true
	}
	return filter.MatchNameEvent(nameEv)
}

// matchRawPathEvent is the enter-side gate for the pathname kinds. Like
// matchRawNameEvent it defers the path dimension of a name whose sys_enter read
// faulted (PATH_READ_FAILED): the recovered name only arrives as a fixup record
// at sys_exit, and handlePathExit's finishPairForTid applies the filter then.
// A name the fixup cannot recover (the read still fails, or the record is lost
// to backpressure) reaches that checkpoint empty, which no non-empty -path
// pattern matches, so the row is dropped there instead of here.
func matchRawPathEvent(filter globalfilter.Filter, ev event.Event) bool {
	pathEv, ok := ev.(*types.PathEvent)
	if !ok || pathEv == nil {
		return false
	}
	if pathEv.PathnameStatus == types.PATH_READ_FAILED {
		return true
	}
	if pathEventTargetRequired(pathEv) && capturedPathNeedsDeferredResolution(pathEv.Dirfd, types.StringValue(pathEv.Pathname[:]),
		pathEv.PathnameStatus, pathEventAllowsEmptyPath(pathEv, true)) {
		return true
	}
	return filter.MatchPathEvent(pathEv)
}

func capturedPathNeedsDeferredResolution(dirfd int32, pathname string, status uint32, allowEmpty bool) bool {
	if status != types.PATH_READ_OK && status != types.PATH_READ_NULL {
		return false
	}
	if pathname == "" {
		return allowEmpty && dirfd != unix.AT_FDCWD
	}
	return status == types.PATH_READ_OK && dirfdPathNeedsResolution(dirfd, pathname)
}
