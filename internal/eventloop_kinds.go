package internal

import (
	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

type runtimeEventDecoder func(raw []byte) event.Event
type runtimeExitHandler func(e *eventLoop, ep *event.Pair) bool
type runtimeEnterFilter func(filter globalfilter.Filter, ev event.Event) bool

// runtimeControlHandler consumes a control event: a ring-buffer record that
// carries state for the event loop instead of a syscall to report. The handler
// owns the event and must recycle it.
type runtimeControlHandler func(e *eventLoop, ev event.Event)

type runtimeEventKind struct {
	enterEventType types.EventType
	exit           runtimeExitHandler
}

type rawEventDirection uint8

const (
	rawEnterEvent rawEventDirection = iota
	rawExitEvent
	// rawControlEvent is neither side of a syscall pair. It updates event-loop
	// state (currently: the post-exec comm of a tid) and is never emitted as a
	// row.
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

func rawDecoder[T any, P eventPtr[T]](decode func([]byte) P) runtimeEventDecoder {
	return func(raw []byte) event.Event {
		ev := decode(raw)
		if ev == nil {
			return nil
		}
		return ev
	}
}

func typedRuntimeControl[T any, P eventPtr[T]](handle func(*eventLoop, P)) runtimeControlHandler {
	return func(e *eventLoop, ev event.Event) {
		typed, ok := ev.(P)
		if !ok {
			e.notifyWarning("Dropped malformed control event")
			ev.Recycle()
			return
		}
		handle(e, typed)
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
		{enterEventType: types.ENTER_FD_EVENT, exit: typedRuntimeExit((*eventLoop).handleFdExit)},
		{enterEventType: types.ENTER_DUP3_EVENT, exit: typedRuntimeExit((*eventLoop).handleDup3Exit)},
		{enterEventType: types.ENTER_OPEN_BY_HANDLE_AT_EVENT, exit: typedRuntimeExit((*eventLoop).handleOpenByHandleAtExit)},
		{enterEventType: types.ENTER_SOCKET_EVENT, exit: typedRuntimeExit((*eventLoop).handleSocketExit)},
		{enterEventType: types.ENTER_SOCKETPAIR_EVENT, exit: typedRuntimeExit((*eventLoop).handleSocketpairExit)},
		{enterEventType: types.ENTER_ACCEPT_EVENT, exit: typedRuntimeExit((*eventLoop).handleAcceptExit)},
		{enterEventType: types.ENTER_PIPE_EVENT, exit: typedRuntimeExit((*eventLoop).handlePipeExit)},
		{enterEventType: types.ENTER_EVENTFD_EVENT, exit: typedRuntimeExit((*eventLoop).handleEventfdExit)},
		{enterEventType: types.ENTER_EPOLL_CTL_EVENT, exit: typedRuntimeExit((*eventLoop).handleEpollCtlExit)},
		{enterEventType: types.ENTER_POLL_EVENT, exit: typedRuntimeExit((*eventLoop).handlePollExit)},
		{enterEventType: types.ENTER_TWO_FD_EVENT, exit: typedRuntimeExit((*eventLoop).handleTwoFdExit)},
		{enterEventType: types.ENTER_MEM_EVENT, exit: typedRuntimeExit((*eventLoop).handleMemExit)},
		{enterEventType: types.ENTER_SLEEP_EVENT, exit: typedRuntimeExit((*eventLoop).handleSleepExit)},
		{enterEventType: types.ENTER_KEYCTL_EVENT, exit: typedRuntimeExit((*eventLoop).handleKeyctlExit)},
		{enterEventType: types.ENTER_PTRACE_EVENT, exit: typedRuntimeExit((*eventLoop).handlePtraceExit)},
		{enterEventType: types.ENTER_PERF_OPEN_EVENT, exit: typedRuntimeExit((*eventLoop).handlePerfOpenExit)},
		{enterEventType: types.ENTER_NULL_EVENT, exit: typedRuntimeExit((*eventLoop).handleNullExit)},
		{enterEventType: types.ENTER_FCNTL_EVENT, exit: typedRuntimeExit((*eventLoop).handleFcntlExit)},
	}
}

func rawRuntimeEvents() []rawRuntimeEvent {
	return []rawRuntimeEvent{
		enterRaw(types.ENTER_OPEN_EVENT, rawDecoder[types.OpenEvent](types.NewOpenEventFast), matchRawOpenEvent),
		exitRaw(types.EXIT_OPEN_EVENT, rawDecoder[types.RetEvent](types.NewRetEventFast)),
		enterRaw(types.ENTER_FD_EVENT, rawDecoder[types.FdEvent](types.NewFdEventFast), nil),
		exitRaw(types.EXIT_FD_EVENT, rawDecoder[types.FdEvent](types.NewFdEventFast)),
		enterRaw(types.ENTER_NULL_EVENT, rawDecoder[types.NullEvent](types.NewNullEventFast), nil),
		exitRaw(types.EXIT_NULL_EVENT, rawDecoder[types.NullEvent](types.NewNullEventFast)),
		exitRaw(types.EXIT_RET_EVENT, rawDecoder[types.RetEvent](types.NewRetEventFast)),
		enterRaw(types.ENTER_NAME_EVENT, rawDecoder[types.NameEvent](types.NewNameEventFast), matchRawNameEvent),
		enterRaw(types.ENTER_PATH_EVENT, rawDecoder[types.PathEvent](types.NewPathEventFast), matchRawPathEvent),
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
		exitRaw(types.EXIT_EVENTFD_EVENT, rawDecoder[types.EventfdEvent](types.NewEventfdEventFast)),
		enterRaw(types.ENTER_EPOLL_CTL_EVENT, rawDecoder[types.EpollCtlEvent](types.NewEpollCtlEventFast), nil),
		enterRaw(types.ENTER_POLL_EVENT, rawDecoder[types.PollEvent](types.NewPollEventFast), nil),
		enterRaw(types.ENTER_TWO_FD_EVENT, rawDecoder[types.TwoFdEvent](types.NewTwoFdEventFast), nil),
		enterRaw(types.ENTER_MEM_EVENT, rawDecoder[types.MemEvent](types.NewMemEventFast), nil),
		enterRaw(types.ENTER_SLEEP_EVENT, rawDecoder[types.SleepEvent](types.NewSleepEventFast), nil),
		enterRaw(types.ENTER_EXEC_EVENT, rawDecoder[types.ExecEvent](types.NewExecEventFast), nil),
		enterRaw(types.ENTER_KEYCTL_EVENT, rawDecoder[types.KeyctlEvent](types.NewKeyctlEventFast), nil),
		enterRaw(types.ENTER_PTRACE_EVENT, rawDecoder[types.PtraceEvent](types.NewPtraceEventFast), nil),
		enterRaw(types.ENTER_PERF_OPEN_EVENT, rawDecoder[types.PerfOpenEvent](types.NewPerfOpenEventFast), nil),
		controlRaw(types.PROCESS_EXEC_EVENT, rawDecoder[types.ProcessExecEvent](types.NewProcessExecEventFast),
			typedRuntimeControl((*eventLoop).handleProcessExecEvent)),
		// The open-name fixup reuses struct open_event because that is exactly
		// what it carries: the enter payload's filename, read a second time at
		// sys_exit once the kernel had faulted the page in. It needs no decoder
		// or Go type of its own, only its own event type so the dispatch table
		// routes it to the control path instead of building a pair from it.
		controlRaw(types.OPEN_NAME_FIXUP_EVENT, rawDecoder[types.OpenEvent](types.NewOpenEventFast),
			typedRuntimeControl((*eventLoop).handleOpenNameFixupEvent)),
	}
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
	if openEv.Filename[0] == 0 {
		return filter.MatchOpenEventComm(openEv)
	}
	return filter.MatchOpenEvent(openEv)
}

func matchRawNameEvent(filter globalfilter.Filter, ev event.Event) bool {
	nameEv, ok := ev.(*types.NameEvent)
	return ok && filter.MatchNameEvent(nameEv)
}

func matchRawPathEvent(filter globalfilter.Filter, ev event.Event) bool {
	pathEv, ok := ev.(*types.PathEvent)
	return ok && filter.MatchPathEvent(pathEv)
}
