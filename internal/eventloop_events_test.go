package internal

import (
	"context"
	"testing"
	"time"
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
