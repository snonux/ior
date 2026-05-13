package internal

import (
	"context"
	"strings"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

func TestEventsStopsOnContextCancelWithoutRawData(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	rawCh := make(chan []byte)
	ctx, cancel := context.WithCancel(context.Background())
	out := el.events(ctx, rawCh)

	cancel()

	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("expected output channel to be closed after cancellation")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for output channel to close after cancellation")
	}
}

// TestEventsPanicInCallbackIsRecoveredAndNotified verifies that a panic inside
// a raw event handler does not crash the events() goroutine. The goroutine
// must recover, emit a warning via warningCb, and continue processing
// subsequent events rather than closing the output channel prematurely.
func TestEventsPanicInCallbackIsRecoveredAndNotified(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{synchronousRawProcessing: false})
	warnings := make(chan string, 4)
	el.warningCb = func(message string) { warnings <- message }

	// Install a handler for ENTER_OPEN_EVENT that always panics.
	el.rawHandlers[types.ENTER_OPEN_EVENT] = func(_ []byte, _ chan<- *event.Pair) {
		panic("injected test panic")
	}

	rawCh := make(chan []byte, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := el.events(ctx, rawCh)

	// Send a raw payload whose first byte is ENTER_OPEN_EVENT to trigger the panic handler.
	rawCh <- []byte{byte(types.ENTER_OPEN_EVENT)}

	// The goroutine must survive; wait briefly and then cancel context cleanly.
	select {
	case msg := <-warnings:
		if !strings.Contains(msg, "injected test panic") {
			t.Fatalf("unexpected warning message: %q", msg)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for panic-recovery warning")
	}

	// Cancel context and confirm the channel closes normally (goroutine is still alive).
	cancel()

	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("expected output channel to be closed after cancellation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for output channel to close after cancellation")
	}
}

func TestEventsIgnoresEmptyRawPayload(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	rawCh := make(chan []byte, 1)
	ctx, cancel := context.WithCancel(context.Background())
	out := el.events(ctx, rawCh)

	rawCh <- nil

	select {
	case ep := <-out:
		t.Fatalf("expected no event for empty raw payload, got %#v", ep)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("expected output channel to be closed after cancellation")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for output channel to close after cancellation")
	}
}
