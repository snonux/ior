package internal

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"ior/internal/benchutil"
	"ior/internal/event"
	"ior/internal/types"
)

// The tests in this file pin the contract of run(), the production path
// every mode uses: raw records are decoded and their pairs emitted on one
// goroutine, so pairs and decode-side warnings reach the callbacks in stream
// order, nothing is decoded ahead of emission, and every pair produced
// before the loop stops (ctx cancellation or a closed rawCh) is emitted and
// counted.

const (
	emitOrderTestTid       = 4242
	emitOrderTestTimeStep  = 1000
	emitOrderTestStartTime = 1_000_000
	emitOrderTestWait      = 5 * time.Second
)

// newEmitOrderEventLoop builds an event loop with its raw handlers
// registered and a cached comm for the synthetic tid, which keeps the enter
// path off procfs.
func newEmitOrderEventLoop(t *testing.T) *eventLoop {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.initRawHandlers()
	el.setCachedComm(emitOrderTestTid, "emitorder")
	return el
}

// emitOrderTestTime is the enter timestamp of the i-th generated pair; the
// tests identify pairs (and check their order) by it.
func emitOrderTestTime(i int) uint64 {
	return emitOrderTestStartTime + uint64(i)*emitOrderTestTimeStep
}

// syncPairStream returns the enter/exit sync pairs first..first+n-1 for one
// tid, in order.
func syncPairStream(t *testing.T, first, n int) [][]byte {
	t.Helper()
	gen := benchutil.NewEventGenerator()
	stream := make([][]byte, 0, 2*n)
	for i := first; i < first+n; i++ {
		enter, exit, err := gen.NullPair(emitOrderTestTime(i), emitOrderTestTid, emitOrderTestTid,
			types.SYS_ENTER_SYNC, types.SYS_EXIT_SYNC)
		if err != nil {
			t.Fatalf("NullPair(%d) error = %v", i, err)
		}
		stream = append(stream, enter, exit)
	}
	return stream
}

// filledRawChannel returns a raw channel pre-loaded with stream.
func filledRawChannel(stream [][]byte) chan []byte {
	rawCh := make(chan []byte, len(stream))
	for _, raw := range stream {
		rawCh <- raw
	}
	return rawCh
}

// unhandledRawRecord returns a one-byte raw record whose event type has no
// registered handler, which processRawEvent reports through notifyWarning.
func unhandledRawRecord(t *testing.T, el *eventLoop) []byte {
	t.Helper()
	for b := 255; b >= 0; b-- {
		if _, ok := el.rawHandlers[types.EventType(b)]; !ok {
			return []byte{byte(b)}
		}
	}
	t.Fatal("every one-byte event type has a raw handler")
	return nil
}

// streamLog records what the pair and warning callbacks saw, in callback
// order: the enter timestamp of each pair, or the warning text.
type streamLog struct {
	entries []streamLogEntry
}

type streamLogEntry struct {
	pairTime uint64
	warning  string
}

func (l *streamLog) attach(el *eventLoop) {
	el.SetPrintCallback(func(ep *event.Pair) {
		l.entries = append(l.entries, streamLogEntry{pairTime: ep.EnterEv.GetTime()})
		ep.Recycle()
	})
	el.SetWarningCallback(func(message string) {
		l.entries = append(l.entries, streamLogEntry{warning: message})
	})
}

func (l *streamLog) pairTimes() []uint64 {
	var times []uint64
	for _, entry := range l.entries {
		if entry.warning == "" {
			times = append(times, entry.pairTime)
		}
	}
	return times
}

// requireOrderedPairs asserts that times holds exactly the enter timestamps
// of pairs 0..want-1, in production order.
func requireOrderedPairs(t *testing.T, times []uint64, want int) {
	t.Helper()
	if len(times) != want {
		t.Fatalf("emitted %d pairs, want %d", len(times), want)
	}
	for i, got := range times {
		if exp := emitOrderTestTime(i); got != exp {
			t.Fatalf("pair %d has enter time %d, want %d (order broken)", i, got, exp)
		}
	}
}

// requireEveryProducedPairEmitted checks the statistics invariant that holds
// however run() stopped: every pair produced was emitted and counted, and
// every raw record taken from rawCh was counted as a tracepoint.
func requireEveryProducedPairEmitted(t *testing.T, el *eventLoop, emitted, rawConsumed int) {
	t.Helper()
	if el.numSyscalls != uint(emitted) {
		t.Fatalf("numSyscalls = %d, but %d pairs were emitted", el.numSyscalls, emitted)
	}
	if el.numSyscallsAfterFilter != uint(emitted) {
		t.Fatalf("numSyscallsAfterFilter = %d, but %d pairs were emitted", el.numSyscallsAfterFilter, emitted)
	}
	if el.numTracepoints != uint(rawConsumed) {
		t.Fatalf("numTracepoints = %d, but %d raw records were consumed", el.numTracepoints, rawConsumed)
	}
}

// TestRunKeepsDecodeWarningsInStreamOrder pins that a warning raised while
// decoding reaches the warning callback after every pair decoded before it
// and before every pair decoded after it. The TUI stamps both from one
// sequencer, so this is the order of its stream rows.
func TestRunKeepsDecodeWarningsInStreamOrder(t *testing.T) {
	const before, after = 100, 3
	el := newEmitOrderEventLoop(t)
	var log streamLog
	log.attach(el)

	stream := syncPairStream(t, 0, before)
	stream = append(stream, unhandledRawRecord(t, el))
	stream = append(stream, syncPairStream(t, before, after)...)
	rawCh := filledRawChannel(stream)
	close(rawCh)

	el.run(context.Background(), rawCh)

	if len(log.entries) != before+1+after {
		t.Fatalf("callbacks saw %d entries, want %d", len(log.entries), before+1+after)
	}
	for i, entry := range log.entries {
		isWarning := entry.warning != ""
		if isWarning != (i == before) {
			t.Fatalf("entry %d warning=%q; the only warning must be entry %d", i, entry.warning, before)
		}
	}
	if !strings.Contains(log.entries[before].warning, "Dropped unhandled raw event type") {
		t.Fatalf("unexpected warning %q", log.entries[before].warning)
	}
	requireOrderedPairs(t, log.pairTimes(), before+after)
}

// TestRunDoesNotDecodeAheadOfEmission pins that no raw record is decoded
// while a pair is being emitted: when the callback sees pair i, exactly the
// 2(i+1) records that produced pairs 0..i have left rawCh. A decoder running
// ahead of emission is what let decode warnings overtake pairs and a stopped
// trace keep emitting into the next session.
func TestRunDoesNotDecodeAheadOfEmission(t *testing.T) {
	const n = 64
	el := newEmitOrderEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, 0, n))
	close(rawCh)

	emitted := 0
	firstAhead := ""
	el.SetPrintCallback(func(ep *event.Pair) {
		if want := 2 * (n - emitted - 1); len(rawCh) != want && firstAhead == "" {
			firstAhead = fmt.Sprintf("emitting pair %d with %d raw records left, want %d", emitted, len(rawCh), want)
		}
		emitted++
		ep.Recycle()
	})

	el.run(context.Background(), rawCh)

	if firstAhead != "" {
		t.Fatal(firstAhead)
	}
	if emitted != n {
		t.Fatalf("emitted %d pairs, want %d", emitted, n)
	}
}

// TestRunStopsPromptlyAfterCancel pins how much a cancelled run can still
// emit - what a TUI restart (tracer.stop() then resetStreamBuffer) can leak
// into the next session. Nothing is decoded ahead, so the only pairs after
// the one that cancelled come from raw records the loop's select picked over
// ctx.Done(); each pick is a coin flip, so a backlog of hundreds of pairs
// (as a buffered handoff produced) is out of reach while every emitted pair
// is still accounted for.
func TestRunStopsPromptlyAfterCancel(t *testing.T) {
	const (
		n          = 512
		cancelAt   = 10
		trials     = 20
		maxTrailer = 32 // P(>= 64 consecutive rawCh picks) = 2^-64
	)
	for trial := 0; trial < trials; trial++ {
		el := newEmitOrderEventLoop(t)
		rawCh := filledRawChannel(syncPairStream(t, 0, n))
		ctx, cancel := context.WithCancel(context.Background())

		var times []uint64
		el.SetPrintCallback(func(ep *event.Pair) {
			times = append(times, ep.EnterEv.GetTime())
			if len(times) == cancelAt+1 {
				cancel()
			}
			ep.Recycle()
		})

		el.run(ctx, rawCh)
		cancel()

		if trailer := len(times) - (cancelAt + 1); trailer < 0 || trailer > maxTrailer {
			t.Fatalf("trial %d: %d pairs emitted after the cancelling one, want 0..%d", trial, trailer, maxTrailer)
		}
		requireOrderedPairs(t, times, len(times))
		requireEveryProducedPairEmitted(t, el, len(times), 2*n-len(rawCh))
	}
}

// TestRunEmitsEveryProducedPairOnCancel is the shutdown guarantee for ctx
// cancellation: the pair whose emission cancels the run and every pair
// produced afterwards are emitted and counted.
func TestRunEmitsEveryProducedPairOnCancel(t *testing.T) {
	const n = 256
	el := newEmitOrderEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, 0, n))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var times []uint64
	el.SetPrintCallback(func(ep *event.Pair) {
		if len(times) == 0 {
			cancel()
		}
		times = append(times, ep.EnterEv.GetTime())
		ep.Recycle()
	})

	el.run(ctx, rawCh)

	if len(times) == 0 {
		t.Fatal("no pair was emitted")
	}
	requireOrderedPairs(t, times, len(times))
	requireEveryProducedPairEmitted(t, el, len(times), 2*n-len(rawCh))
}

// TestRunEmitsAllPairsOnRawChannelClose covers the other stop path: rawCh
// closing (ring buffer torn down) with records still queued.
func TestRunEmitsAllPairsOnRawChannelClose(t *testing.T) {
	const n = 256
	el := newEmitOrderEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, 0, n))
	close(rawCh)
	var log streamLog
	log.attach(el)

	el.run(context.Background(), rawCh)

	requireOrderedPairs(t, log.pairTimes(), n)
	requireEveryProducedPairEmitted(t, el, n, 2*n)
}

// TestRunRecoversHandlerPanicInStreamOrder checks panic recovery on the
// production path: a panicking handler neither stops the run nor drops or
// reorders the pairs around it, and its warning lands between them.
func TestRunRecoversHandlerPanicInStreamOrder(t *testing.T) {
	const before, after = 4, 4
	el := newEmitOrderEventLoop(t)
	var log streamLog
	log.attach(el)
	el.rawHandlers[types.ENTER_OPEN_EVENT] = func(_ []byte, _ chan<- *event.Pair) {
		panic("injected test panic")
	}

	stream := syncPairStream(t, 0, before)
	stream = append(stream, []byte{byte(types.ENTER_OPEN_EVENT)})
	stream = append(stream, syncPairStream(t, before, after)...)
	rawCh := filledRawChannel(stream)
	close(rawCh)

	el.run(context.Background(), rawCh)

	if len(log.entries) != before+1+after {
		t.Fatalf("callbacks saw %d entries, want %d", len(log.entries), before+1+after)
	}
	if !strings.Contains(log.entries[before].warning, "injected test panic") {
		t.Fatalf("entry %d = %+v, want the panic-recovery warning", before, log.entries[before])
	}
	requireOrderedPairs(t, log.pairTimes(), before+after)
	requireEveryProducedPairEmitted(t, el, before+after, len(stream))
}

// TestRunRecoversPanicAfterPairCompleted covers a handler that panics after
// it has completed a pair: the pair is still emitted and counted.
func TestRunRecoversPanicAfterPairCompleted(t *testing.T) {
	el := newEmitOrderEventLoop(t)
	var log streamLog
	log.attach(el)
	stream := syncPairStream(t, 0, 2)
	exitType := types.EventType(stream[1][0])
	exitHandler := el.rawHandlers[exitType]
	el.rawHandlers[exitType] = func(raw []byte, ch chan<- *event.Pair) {
		exitHandler(raw, ch)
		panic("injected panic after pair")
	}
	rawCh := filledRawChannel(stream)
	close(rawCh)

	el.run(context.Background(), rawCh)

	requireOrderedPairs(t, log.pairTimes(), 2)
	requireEveryProducedPairEmitted(t, el, 2, 4)
	if warnings := len(log.entries) - 2; warnings != 2 {
		t.Fatalf("got %d panic-recovery warnings, want 2", warnings)
	}
}

// TestRunReturnsWhenCancelledWithoutRawData checks that an idle run stops
// on ctx cancellation.
func TestRunReturnsWhenCancelledWithoutRawData(t *testing.T) {
	el := newEmitOrderEventLoop(t)
	ctx, cancel := context.WithCancel(context.Background())
	go el.run(ctx, make(chan []byte))
	cancel()
	select {
	case <-el.done:
	case <-time.After(emitOrderTestWait):
		t.Fatal("run() did not return after cancellation")
	}
}
