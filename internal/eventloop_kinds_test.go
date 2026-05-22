package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandleTracepointExitDispatchesViaRuntimeKindRegistry(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	called := false
	el.exitHandlers = map[types.EventType]runtimeExitHandler{
		types.ENTER_FD_EVENT: func(_ *eventLoop, ep *event.Pair) bool {
			called = true
			ep.Comm = "registry"
			return true
		},
	}

	ep := &event.Pair{
		EnterEv: &types.FdEvent{EventType: types.ENTER_FD_EVENT, TraceId: types.SYS_ENTER_READ, Tid: defaultTid},
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_READ, Tid: defaultTid},
	}

	if ok := el.handleTracepointExit(ep); !ok {
		t.Fatal("handleTracepointExit returned false")
	}
	if !called {
		t.Fatal("registered runtime kind handler was not called")
	}
	if ep.Comm != "registry" {
		t.Fatalf("ep.Comm = %q, want registry", ep.Comm)
	}
}

func TestHandleTracepointExitRejectsMismatchedRuntimeKind(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	ep := &event.Pair{
		EnterEv: &types.NullEvent{EventType: types.ENTER_FD_EVENT, TraceId: types.SYS_ENTER_READ, Tid: defaultTid},
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_READ, Tid: defaultTid},
	}

	if ok := el.handleTracepointExit(ep); ok {
		t.Fatal("expected mismatched runtime kind to be rejected")
	}

	select {
	case msg := <-warnings:
		if msg != "Dropped malformed enter event" {
			t.Fatalf("unexpected warning %q", msg)
		}
	default:
		t.Fatal("expected warning for mismatched runtime kind")
	}
}

func TestTracepointExitedFinalizesRuntimeKindPair(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	fd := int32(42)
	tracked := file.NewFd(fd, "/tmp/read-source", 0)
	el.fdState().set(fd, tracked)

	enter := &types.FdEvent{
		EventType: types.ENTER_FD_EVENT,
		TraceId:   types.SYS_ENTER_READ,
		Time:      1000,
		Pid:       defaultPid,
		Tid:       defaultTid,
		Fd:        fd,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_READ,
		Time:      1256,
		Pid:       defaultPid,
		Tid:       defaultTid,
		Ret:       128,
		RetType:   types.READ_CLASSIFIED,
	}

	el.tracepointEntered(enter)
	out := make(chan *event.Pair, 1)
	el.tracepointExited(exit, out)

	select {
	case ep := <-out:
		if ep.Bytes != 128 {
			t.Fatalf("ep.Bytes = %d, want 128", ep.Bytes)
		}
		if ep.Duration != 256 {
			t.Fatalf("ep.Duration = %d, want 256", ep.Duration)
		}
		if ep.File == tracked {
			t.Fatal("expected emitted fd file to be frozen as a duplicate")
		}
		if got := ep.FileName(); got != "/tmp/read-source" {
			t.Fatalf("ep.FileName() = %q, want /tmp/read-source", got)
		}
	default:
		t.Fatal("expected finalized pair to be emitted")
	}
}

func TestRawRuntimeEventHandlerAppliesEnterFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			File: &globalfilter.StringFilter{Pattern: "keep"},
		},
	})

	_, raw := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, "/tmp/drop", types.SYS_ENTER_NEWSTAT)
	el.processRawEvent(raw, make(chan *event.Pair, 1))

	if _, ok := el.pairs.enters[defaultTid]; ok {
		t.Fatalf("path enter event should have been rejected by the raw enter filter")
	}
}

func TestRuntimeEventKindRegistriesHaveUniqueCoverage(t *testing.T) {
	exitHandlers := make(map[types.EventType]struct{})
	for _, kind := range runtimeEventKinds() {
		if _, exists := exitHandlers[kind.enterEventType]; exists {
			t.Fatalf("duplicate runtime event kind for %v", kind.enterEventType)
		}
		exitHandlers[kind.enterEventType] = struct{}{}
		if kind.exit == nil {
			t.Fatalf("nil runtime exit handler for %v", kind.enterEventType)
		}
	}

	rawHandlers := make(map[types.EventType]rawEventDirection)
	for _, rawEvent := range rawRuntimeEvents() {
		if _, exists := rawHandlers[rawEvent.eventType]; exists {
			t.Fatalf("duplicate raw runtime event for %v", rawEvent.eventType)
		}
		rawHandlers[rawEvent.eventType] = rawEvent.direction
		if rawEvent.decode == nil {
			t.Fatalf("nil raw decoder for %v", rawEvent.eventType)
		}
		if rawEvent.direction == rawEnterEvent {
			if _, exists := exitHandlers[rawEvent.eventType]; !exists {
				t.Fatalf("enter raw event %v has no runtime exit handler", rawEvent.eventType)
			}
		}
	}

	for enterEventType := range exitHandlers {
		if direction, exists := rawHandlers[enterEventType]; !exists || direction != rawEnterEvent {
			t.Fatalf("runtime event kind %v has no enter raw handler", enterEventType)
		}
	}
}
