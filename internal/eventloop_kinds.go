package internal

import (
	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

type runtimeEventDecoder func(raw []byte) event.Event
type runtimeExitHandler func(e *eventLoop, ep *event.Pair) bool
type runtimeEnterFilter func(filter globalfilter.Filter, ev event.Event) bool

type runtimeEventKind struct {
	enterEventType types.EventType
	exit           runtimeExitHandler
}

type rawEventDirection uint8

const (
	rawEnterEvent rawEventDirection = iota
	rawExitEvent
)

type rawRuntimeEvent struct {
	eventType types.EventType
	direction rawEventDirection
	decode    runtimeEventDecoder
	filter    runtimeEnterFilter
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
	}
}

func enterRaw(eventType types.EventType, decode runtimeEventDecoder, filter runtimeEnterFilter) rawRuntimeEvent {
	return rawRuntimeEvent{eventType: eventType, direction: rawEnterEvent, decode: decode, filter: filter}
}

func exitRaw(eventType types.EventType, decode runtimeEventDecoder) rawRuntimeEvent {
	return rawRuntimeEvent{eventType: eventType, direction: rawExitEvent, decode: decode}
}

func matchRawOpenEvent(filter globalfilter.Filter, ev event.Event) bool {
	openEv, ok := ev.(*types.OpenEvent)
	return ok && filter.MatchOpenEvent(openEv)
}

func matchRawNameEvent(filter globalfilter.Filter, ev event.Event) bool {
	nameEv, ok := ev.(*types.NameEvent)
	return ok && filter.MatchNameEvent(nameEv)
}

func matchRawPathEvent(filter globalfilter.Filter, ev event.Event) bool {
	pathEv, ok := ev.(*types.PathEvent)
	return ok && filter.MatchPathEvent(pathEv)
}
