package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandleEpollCtlExitUsesEpollInstanceFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(41, 90, file.NewFd(41, "anon_inode:[eventpoll]", -1))

	enter := &types.EpollCtlEvent{
		EventType: types.ENTER_EPOLL_CTL_EVENT,
		TraceId:   types.SYS_ENTER_EPOLL_CTL,
		Time:      100,
		Pid:       90,
		Tid:       91,
		Epfd:      41,
		Op:        1,
		Fd:        42,
		Events:    1,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_EPOLL_CTL,
		Time:      200,
		Ret:       0,
		Pid:       90,
		Tid:       91,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleEpollCtlExit(ep, enter); !ok {
		t.Fatal("handleEpollCtlExit returned false")
	}
	if ep.File == nil || ep.File.FD() != 41 {
		t.Fatalf("expected resolved epoll instance fd 41, got file=%v", ep.File)
	}
}

func TestHandleEpollCtlExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.EpollCtlEvent{
		EventType: types.ENTER_EPOLL_CTL_EVENT,
		TraceId:   types.SYS_ENTER_EPOLL_CTL,
		Time:      100,
		Pid:       92,
		Tid:       93,
		Epfd:      51,
		Op:        1,
		Fd:        52,
		Events:    1,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_EPOLL_CTL,
		Time:      200,
		Ret:       0,
		Pid:       92,
		Tid:       93,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleEpollCtlExit(ep, enter); ok {
		t.Fatal("handleEpollCtlExit should reject pair due to filter mismatch")
	}
}

func TestInitRawHandlersRegistersPollingEvents(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_EPOLL_CTL_EVENT]; !ok {
		t.Fatal("ENTER_EPOLL_CTL_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_POLL_EVENT]; !ok {
		t.Fatal("ENTER_POLL_EVENT handler is not registered")
	}
}

func TestHandlePollExitCarriesCommAndAppliesFilter(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{})
		enter := &types.PollEvent{
			EventType: types.ENTER_POLL_EVENT,
			TraceId:   types.SYS_ENTER_POLL,
			Time:      300,
			Pid:       120,
			Tid:       121,
			Nfds:      2,
			TimeoutNs: 5_000_000,
		}
		exit := &types.RetEvent{
			EventType: types.EXIT_RET_EVENT,
			TraceId:   types.SYS_EXIT_POLL,
			Time:      320,
			Ret:       1,
			Pid:       120,
			Tid:       121,
		}
		ep := &event.Pair{EnterEv: enter, ExitEv: exit}

		if ok := el.handlePollExit(ep, enter); !ok {
			t.Fatal("handlePollExit returned false")
		}
		if ep.Comm != "" {
			t.Fatalf("expected empty comm for unresolved tid, got %q", ep.Comm)
		}
	})

	t.Run("filtered", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{
			filter: globalfilter.Filter{
				Syscall: &globalfilter.StringFilter{Pattern: "openat"},
			},
		})
		enter := &types.PollEvent{
			EventType: types.ENTER_POLL_EVENT,
			TraceId:   types.SYS_ENTER_POLL,
			Time:      300,
			Pid:       120,
			Tid:       121,
			Nfds:      2,
			TimeoutNs: 5_000_000,
		}
		exit := &types.RetEvent{
			EventType: types.EXIT_RET_EVENT,
			TraceId:   types.SYS_EXIT_POLL,
			Time:      320,
			Ret:       1,
			Pid:       120,
			Tid:       121,
		}
		ep := &event.Pair{EnterEv: enter, ExitEv: exit}

		if ok := el.handlePollExit(ep, enter); ok {
			t.Fatal("handlePollExit should reject pair due to filter mismatch")
		}
	})
}

func TestHandlePollExitResolvesEpollFDAndCarriesWaitMetadata(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(61, 130, file.NewFd(61, "anon_inode:[eventpoll]", -1))
	enter := &types.PollEvent{
		EventType:     types.ENTER_POLL_EVENT,
		TraceId:       types.SYS_ENTER_EPOLL_WAIT,
		Time:          400,
		Pid:           130,
		Tid:           131,
		Nfds:          4,
		TimeoutNs:     250_000_000,
		Fd:            61,
		SchemaVersion: types.POLL_EVENT_SCHEMA_VERSION,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_EPOLL_WAIT,
		Time:      420,
		Ret:       1,
		Pid:       130,
		Tid:       131,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePollExit(ep, enter); !ok {
		t.Fatal("handlePollExit returned false")
	}
	if ep.File == nil || ep.File.FD() != 61 {
		t.Fatalf("expected resolved epoll fd 61, got %v", ep.File)
	}
	if ep.Nfds != 4 || ep.TimeoutNs != 250_000_000 {
		t.Fatalf("poll metadata = %d/%d, want 4/250000000", ep.Nfds, ep.TimeoutNs)
	}
}
