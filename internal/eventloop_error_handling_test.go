package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
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

func TestProcessRawEventMalformedKnownTypeDoesNotPanicAndNotifies(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	pairCh := make(chan *event.Pair, 1)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("processRawEvent panicked: %v", r)
		}
	}()

	el.processRawEvent([]byte{byte(types.ENTER_OPEN_EVENT)}, pairCh)

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

func TestDecodeRawEventMalformedNotifies(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	decoded, ok := decodeRawEvent(el, types.ENTER_OPEN_EVENT, []byte{byte(types.ENTER_OPEN_EVENT)}, types.NewOpenEventFast)
	if ok || decoded != nil {
		t.Fatalf("expected malformed raw event decode to fail, got ok=%v decoded=%v", ok, decoded)
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

// unknownEvent is a minimal event.Event stub used to exercise the default
// branch of handleTracepointExit (an enter-event type not covered by any case).
type unknownEvent struct{}

func (unknownEvent) String() string            { return "unknownEvent" }
func (unknownEvent) GetTraceId() types.TraceId { return 0 }
func (unknownEvent) GetPid() uint32            { return 0 }
func (unknownEvent) GetTid() uint32            { return 0 }
func (unknownEvent) GetTime() uint64           { return 0 }
func (unknownEvent) Equals(other any) bool     { return false }
func (unknownEvent) Recycle()                  {}

func TestHandleTracepointExitUnknownTypeDropsMalformedEvent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	// Wrap an unknown enter-event type to hit the default branch of the type switch.
	ep := event.NewPair(unknownEvent{})

	ok := el.handleTracepointExit(ep)
	if ok {
		t.Fatal("expected handleTracepointExit to return false for unknown enter-event type")
	}

	select {
	case msg := <-warnings:
		if msg != "Dropped malformed enter event" {
			t.Fatalf("unexpected warning %q", msg)
		}
	default:
		t.Fatal("expected warning notification for unknown enter-event type")
	}
}

func TestTracepointEnteredMissingCommWithCommFilterNotifies(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Comm: &globalfilter.StringFilter{Pattern: "system"},
		},
	})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) { warnings <- message }

	_, enterRaw := makeEnterFdEvent(t, defaulTime, defaultPid, defaultTid, 20, types.SYS_ENTER_WRITE)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("tracepointEntered panicked: %v", r)
		}
	}()

	el.tracepointEntered(types.NewFdEvent(enterRaw))

	select {
	case msg := <-warnings:
		if msg == "" {
			t.Fatalf("expected non-empty warning message")
		}
	default:
		t.Fatalf("expected warning notification")
	}

	if _, ok := el.enterEvs[defaultTid]; ok {
		t.Fatalf("expected no enter event to be stored for tid %d", defaultTid)
	}
}
