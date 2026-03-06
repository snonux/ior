package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

func TestTracepointExitedMalformedOpenExitDoesNotPanicAndNotifies(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	enterEv, enterRaw := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	el.tracepointEntered(types.NewOpenEvent(enterRaw))

	_, exitRaw := makeExitNullEvent(t, defaulTime+1, defaultPid, defaultTid, types.SYS_EXIT_OPEN)
	exitEv := types.NewNullEvent(exitRaw)
	pairCh := make(chan *event.Pair, 1)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("tracepointExited panicked: %v", r)
		}
	}()

	el.tracepointExited(exitEv, pairCh)

	select {
	case ep := <-pairCh:
		t.Fatalf("unexpected event produced: %v", ep)
	default:
	}

	select {
	case msg := <-warnings:
		if msg == "" {
			t.Fatalf("expected non-empty warning message")
		}
	default:
		t.Fatalf("expected warning notification")
	}

	if _, ok := el.enterEvs[enterEv.Tid]; ok {
		t.Fatalf("expected enter event to be removed for tid %d", enterEv.Tid)
	}
}

func TestTracepointExitedMalformedOpenByHandleAtExitDoesNotPanicAndNotifies(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	_, enterRaw := makeEnterOpenByHandleAtEvent(t, defaulTime, defaultPid, defaultTid, 0)
	el.tracepointEntered(types.NewOpenByHandleAtEvent(enterRaw))

	_, exitRaw := makeExitNullEvent(t, defaulTime+1, defaultPid, defaultTid, types.SYS_EXIT_OPEN_BY_HANDLE_AT)
	exitEv := types.NewNullEvent(exitRaw)
	pairCh := make(chan *event.Pair, 1)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("tracepointExited panicked: %v", r)
		}
	}()

	el.tracepointExited(exitEv, pairCh)

	select {
	case ep := <-pairCh:
		t.Fatalf("unexpected event produced: %v", ep)
	default:
	}

	select {
	case msg := <-warnings:
		if msg == "" {
			t.Fatalf("expected non-empty warning message")
		}
	default:
		t.Fatalf("expected warning notification")
	}
}

func TestProcessRawEventUnknownTypeDoesNotPanicAndNotifies(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	pairCh := make(chan *event.Pair, 1)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("processRawEvent panicked: %v", r)
		}
	}()

	el.processRawEvent([]byte{255}, pairCh)

	select {
	case ep := <-pairCh:
		t.Fatalf("unexpected event produced: %v", ep)
	default:
	}

	select {
	case msg := <-warnings:
		if msg == "" {
			t.Fatalf("expected non-empty warning message")
		}
	default:
		t.Fatalf("expected warning notification")
	}
}
