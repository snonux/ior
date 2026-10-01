package internal

import (
	"context"
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// Task 5s2: after one record arrives through the select, the loop drains the
// records already waiting in rawCh without a select per record
// (consumeReadyRaw). These tests pin its contract: it takes exactly what is
// ready, never blocks, is bounded, and reports a closed channel.

func readyRawChannel(t *testing.T, n, capacity int) chan []byte {
	t.Helper()
	ch := make(chan []byte, capacity)
	for i := 0; i < n; i++ {
		_, raw := makeEnterNullEvent(t, defaulTime+uint64(i), execCommPid, execCommTid, types.SYS_ENTER_GETPID)
		ch <- raw
	}
	return ch
}

func TestConsumeReadyRawTakesExactlyWhatIsWaiting(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	ch := readyRawChannel(t, 5, 8)
	if !el.consumeReadyRaw(context.Background(), ch, make(chan *event.Pair, 2), nil) {
		t.Fatal("consumeReadyRaw reported a closed channel on an open one")
	}
	if el.numTracepoints != 5 || len(ch) != 0 {
		t.Fatalf("consumed %d records, %d left; want 5 and 0", el.numTracepoints, len(ch))
	}
}

func TestConsumeReadyRawDoesNotBlockOnAnEmptyChannel(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	ch := make(chan []byte, 1)
	if !el.consumeReadyRaw(context.Background(), ch, make(chan *event.Pair, 2), nil) || el.numTracepoints != 0 {
		t.Fatalf("empty channel: consumed %d records", el.numTracepoints)
	}
}

func TestConsumeReadyRawIsBounded(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	ch := readyRawChannel(t, maxReadyBatch+10, maxReadyBatch+10)
	el.consumeReadyRaw(context.Background(), ch, make(chan *event.Pair, 2), nil)
	if el.numTracepoints != maxReadyBatch || len(ch) != 10 {
		t.Fatalf("consumed %d records, %d left; want %d and 10", el.numTracepoints, len(ch), maxReadyBatch)
	}
}

func TestConsumeReadyRawReportsAClosedChannelAfterTheBacklog(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	ch := readyRawChannel(t, 3, 4)
	close(ch)
	if el.consumeReadyRaw(context.Background(), ch, make(chan *event.Pair, 2), nil) {
		t.Fatal("a closed channel was not reported")
	}
	if el.numTracepoints != 3 {
		t.Fatalf("consumed %d records before the close, want the whole backlog (3)", el.numTracepoints)
	}
}

// A cancelled context stops the batch before it takes a record: the stop path
// (drainBacklogAtStop) owns the backlog then, with its own time budget.
func TestConsumeReadyRawStopsAtACancelledContext(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	ch := readyRawChannel(t, 5, 8)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !el.consumeReadyRaw(ctx, ch, make(chan *event.Pair, 2), nil) {
		t.Fatal("consumeReadyRaw reported a closed channel on an open one")
	}
	if el.numTracepoints != 0 || len(ch) != 5 {
		t.Fatalf("consumed %d records, %d left; want none consumed after the cancel", el.numTracepoints, len(ch))
	}
}
