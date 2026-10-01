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

// TestRunStopsPromptlyAfterCancel pins what a cancelled run does with the raw
// backlog: it decodes the records already buffered at the cancel (bounded by
// the snapshot taken then, see drainBacklogAtStop) and stops. Everything still
// happens inside run(), so nothing is emitted after it returned - what a TUI
// restart (tracer.stop() then resetStreamBuffer) could otherwise leak into the
// next session, as a buffered handoff did. Whether the select or the drain
// consumes a given record is a coin flip, so the assertion is the accounting
// that holds for both: every record of the backlog was taken and every pair it
// formed was emitted (task tq2 - they used to be discarded at stop).
func TestRunStopsPromptlyAfterCancel(t *testing.T) {
	const (
		n        = 512
		cancelAt = 10
		trials   = 20
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
		emittedAtReturn := len(times)

		if len(rawCh) != 0 {
			t.Fatalf("trial %d: %d buffered records left behind by run()", trial, len(rawCh))
		}
		if emittedAtReturn != n {
			t.Fatalf("trial %d: %d pairs emitted, want all %d", trial, emittedAtReturn, n)
		}
		requireOrderedPairs(t, times, len(times))
		requireEveryProducedPairEmitted(t, el, len(times), 2*n)
		if el.numDiscardedAtStop != 0 {
			t.Fatalf("trial %d: numDiscardedAtStop = %d, want 0", trial, el.numDiscardedAtStop)
		}
		// Nothing may be emitted once run() returned: give a stray goroutine
		// (a late flush, a leaked handoff) a moment to misbehave, then check
		// that the count did not move (and, under -race, that nobody wrote).
		time.Sleep(time.Millisecond)
		if len(times) != emittedAtReturn {
			t.Fatalf("trial %d: %d pairs emitted after run() returned", trial, len(times)-emittedAtReturn)
		}
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

// TestRunEmitsPairPendingAtCancel is the shutdown guarantee for the one
// moment a produced pair is not yet emitted: after the handler that
// completed it returned and before drainPairs ran. Cancelling from the
// pair-emitting callback (as the tests above do) never hits that window,
// so a loop that checked ctx between decode and emission would pass them
// while losing a counted pair here.
//
// Two triggers cancel while pair k is pending: the exit handler itself
// right after completing it, and the warning callback reacting to a panic
// the handler raises after completing it (a TUI stop can land on any
// callback). Both are deterministic; several k cover the first, an early
// and the last pair.
func TestRunEmitsPairPendingAtCancel(t *testing.T) {
	const n = 32
	for _, viaWarning := range []bool{false, true} {
		name := "cancel inside the completing handler"
		if viaWarning {
			name = "cancel from the warning callback"
		}
		t.Run(name, func(t *testing.T) {
			for _, k := range []int{0, 1, 13, n - 1} {
				emitted, warnings := runCancelWithPairPending(t, n, k, viaWarning)
				if emitted < k+1 {
					t.Fatalf("k=%d: emitted %d pairs; pair %d, completed before the cancel, is missing", k, emitted, k)
				}
				wantWarnings := 0
				if viaWarning {
					wantWarnings = 1
				}
				if warnings != wantWarnings {
					t.Fatalf("k=%d: %d warnings, want %d", k, warnings, wantWarnings)
				}
			}
		})
	}
}

// runCancelWithPairPending runs n sync pairs through run() with the exit
// handler wrapped to cancel ctx right after it completed pair k - directly
// or, with viaWarning, by panicking into a warning callback that cancels.
// It checks order and accounting and returns the pairs and warnings seen.
func runCancelWithPairPending(t *testing.T, n, k int, viaWarning bool) (emitted, warnings int) {
	t.Helper()
	el := newEmitOrderEventLoop(t)
	stream := syncPairStream(t, 0, n)
	rawCh := filledRawChannel(stream)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitType := types.EventType(stream[1][0])
	exitHandler := el.rawHandlers[exitType]
	completed := 0
	el.rawHandlers[exitType] = func(raw []byte, ch chan<- *event.Pair) {
		exitHandler(raw, ch)
		completed++
		if completed != k+1 {
			return
		}
		if viaWarning {
			panic("injected panic with a pair pending")
		}
		cancel()
	}
	var times []uint64
	el.SetPrintCallback(func(ep *event.Pair) {
		times = append(times, ep.EnterEv.GetTime())
		ep.Recycle()
	})
	el.SetWarningCallback(func(message string) {
		if !strings.Contains(message, "injected panic with a pair pending") {
			t.Errorf("unexpected warning %q", message)
		}
		warnings++
		cancel()
	})

	el.run(ctx, rawCh)

	requireOrderedPairs(t, times, len(times))
	requireEveryProducedPairEmitted(t, el, len(times), len(stream)-len(rawCh))
	return len(times), warnings
}

// TestRunSurvivesHandlerProducingThreePairs pins that a handler breaking the
// pairs-per-record rule cannot deadlock the loop on the pair channel. Its two
// slots hold a record's own pair plus the held -516 row it may release first
// (task fs2); a third pair is dropped with a warning, the first two are
// emitted in order, and the run goes on to the end of the stream.
func TestRunSurvivesHandlerProducingThreePairs(t *testing.T) {
	const secondTid = emitOrderTestTid + 1
	const thirdTid = emitOrderTestTid + 2
	const after = 3
	el := newEmitOrderEventLoop(t)
	el.setCachedComm(secondTid, "emitorder2")
	el.setCachedComm(thirdTid, "emitorder3")
	var log streamLog
	log.attach(el)

	gen := benchutil.NewEventGenerator()
	secondEnter, secondExit, err := gen.NullPair(emitOrderTestTime(1), secondTid, secondTid,
		types.SYS_ENTER_SYNC, types.SYS_EXIT_SYNC)
	if err != nil {
		t.Fatalf("NullPair error = %v", err)
	}
	thirdEnter, thirdExit, err := gen.NullPair(emitOrderTestTime(100), thirdTid, thirdTid,
		types.SYS_ENTER_SYNC, types.SYS_EXIT_SYNC)
	if err != nil {
		t.Fatalf("NullPair error = %v", err)
	}
	first := syncPairStream(t, 0, 1)
	exitType := types.EventType(first[1][0])
	exitHandler := el.rawHandlers[exitType]
	broken := false
	el.rawHandlers[exitType] = func(raw []byte, ch chan<- *event.Pair) {
		exitHandler(raw, ch)
		if !broken {
			// Complete the other two tids' pairs from the same record.
			broken = true
			exitHandler(secondExit, ch)
			exitHandler(thirdExit, ch)
		}
	}

	stream := [][]byte{secondEnter, thirdEnter, first[0], first[1]}
	stream = append(stream, syncPairStream(t, 2, after)...)
	rawCh := filledRawChannel(stream)
	close(rawCh)

	// On a timeout the run goroutine outlives the test. Cancelling its ctx
	// at cleanup lets a merely slow run stop. The log is read only after
	// el.done: the timeout branch returns via t.Fatal before any read, so a
	// late callback write from the leaked run never races a reader.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go el.run(ctx, rawCh)
	select {
	case <-el.done:
	case <-time.After(emitOrderTestWait):
		t.Fatal("run() hung on a handler that produced three pairs for one record")
	}

	if len(log.entries) != 1+2+after {
		t.Fatalf("callbacks saw %d entries, want %d", len(log.entries), 1+2+after)
	}
	if !strings.Contains(log.entries[0].warning, secondPairPanic) {
		t.Fatalf("entry 0 = %+v, want the extra-pair warning", log.entries[0])
	}
	requireOrderedPairs(t, log.pairTimes(), 2+after)
	// The dropped pair was produced, so it is counted in numSyscalls only.
	if el.numSyscalls != 2+after+1 || el.numSyscallsAfterFilter != 2+after {
		t.Fatalf("numSyscalls=%d numSyscallsAfterFilter=%d, want %d and %d",
			el.numSyscalls, el.numSyscallsAfterFilter, 2+after+1, 2+after)
	}
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
//
// It also pins the resulting order: the panic warning precedes the pair,
// because the pair waits in the channel until the handler has returned
// (processRawEventSafe reports the panic) and only then is drained. At
// 7280fd3 a separate emit goroutine received the pair during the send, so
// the pair could come first. The difference is hypothetical: no real handler
// does any work after sending its pair.
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
	if len(log.entries) != 4 {
		t.Fatalf("callbacks saw %d entries, want 2 warnings and 2 pairs", len(log.entries))
	}
	for i, entry := range log.entries {
		if isWarning := entry.warning != ""; isWarning != (i%2 == 0) {
			t.Fatalf("entry %d = %+v; want warning, pair, warning, pair", i, entry)
		}
		if i%2 == 0 && !strings.Contains(entry.warning, "injected panic after pair") {
			t.Fatalf("entry %d warning %q, want the panic-recovery warning", i, entry.warning)
		}
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
