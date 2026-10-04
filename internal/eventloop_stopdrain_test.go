package internal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"ior/internal/event"
)

// TestRunDrainsBacklogBufferedAtCancel is the core of task tq2: a context that
// is already cancelled while a full backlog sits in rawCh must still get every
// buffered record decoded and emitted - the loop used to return at ctx.Done()
// and RingBuffer.Stop then threw the backlog away uncounted. The select picks
// between a ready record and a ready ctx.Done() at random, so how many records
// the main loop and how many the drain consume varies; the sum must not.
// TestDrainBacklogAtStopDecodesEverythingBuffered isolates the drain itself.
func TestRunDrainsBacklogBufferedAtCancel(t *testing.T) {
	const n = 300
	el := newEmitOrderEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, 0, n))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var times []uint64
	el.SetPrintCallback(func(ep *event.Pair) {
		times = append(times, ep.EnterEv.GetTime())
		ep.Recycle()
	})

	el.run(ctx, rawCh)

	if len(times) != n {
		t.Fatalf("emitted %d pairs, want the %d buffered at the cancel", len(times), n)
	}
	requireOrderedPairs(t, times, n)
	requireEveryProducedPairEmitted(t, el, n, 2*n)
	if el.numDiscardedAtStop != 0 {
		t.Fatalf("numDiscardedAtStop = %d, want 0 for a fully drained backlog", el.numDiscardedAtStop)
	}
	// Negative: a complete drain prints no "discarded" line, so the line stays
	// meaningful when it does appear.
	if stats := el.stats(); strings.Contains(stats, "discarded at stop") {
		t.Fatalf("stats mention discarded records after a complete drain:\n%s", stats)
	}
}

// newDrainHarness returns an event loop with a pairs channel as processRawEvents
// makes it, for tests that call drainBacklogAtStop directly: through run() the
// select would hand a random share of the backlog to the main loop first.
func newDrainHarness(t *testing.T) (*eventLoop, chan *event.Pair) {
	t.Helper()
	return newEmitOrderEventLoop(t), make(chan *event.Pair, 1)
}

// TestDrainBacklogAtStopDecodesEverythingBuffered runs the drain alone: every
// buffered record is decoded, every pair emitted in order, nothing discarded.
func TestDrainBacklogAtStopDecodesEverythingBuffered(t *testing.T) {
	const n = 64
	el, pairs := newDrainHarness(t)
	rawCh := filledRawChannel(syncPairStream(t, 0, n))
	var times []uint64
	el.SetPrintCallback(func(ep *event.Pair) {
		times = append(times, ep.EnterEv.GetTime())
		ep.Recycle()
	})

	el.drainBacklogAtStop(rawCh, pairs, nil)

	requireOrderedPairs(t, times, n)
	requireEveryProducedPairEmitted(t, el, n, 2*n)
	if len(rawCh) != 0 || el.numDiscardedAtStop != 0 {
		t.Fatalf("left %d in rawCh, discarded %d; want a complete drain", len(rawCh), el.numDiscardedAtStop)
	}
}

// TestDrainBacklogAtStopIsBoundedByTheBacklogAtStop pins that only the records
// buffered at the stop are drained. The consumer refills rawCh from inside the
// drain (the probes stay attached until run returned), which a drain that
// chased the producer would follow forever; here the refill is left untouched.
func TestDrainBacklogAtStopIsBoundedByTheBacklogAtStop(t *testing.T) {
	const n, refill = 50, 40
	el, pairs := newDrainHarness(t)
	stream := syncPairStream(t, 0, n)
	extra := syncPairStream(t, n, refill)
	rawCh := make(chan []byte, len(stream)+len(extra))
	for _, raw := range stream {
		rawCh <- raw
	}
	refilled := false
	el.SetPrintCallback(func(ep *event.Pair) {
		if !refilled {
			refilled = true
			for _, raw := range extra {
				rawCh <- raw
			}
		}
		ep.Recycle()
	})

	el.drainBacklogAtStop(rawCh, pairs, nil)

	if el.numTracepoints != uint(len(stream)) {
		t.Fatalf("numTracepoints = %d, want the %d records buffered at the stop", el.numTracepoints, len(stream))
	}
	if len(rawCh) != len(extra) {
		t.Fatalf("%d records left in rawCh, want the %d that arrived after the stop", len(rawCh), len(extra))
	}
	if el.numDiscardedAtStop != 0 {
		t.Fatalf("numDiscardedAtStop = %d: post-stop arrivals are not part of the snapshot", el.numDiscardedAtStop)
	}
}

// TestRunCountsBacklogItCannotDrainInTime is the accounting half: a consumer
// so slow that the budget runs out leaves records undecoded, and they must
// show up as "discarded at stop" (in the statistics and as a warning) instead
// of vanishing. tracepoints + discarded must add up to the backlog, and the
// run must return near the budget instead of waiting for the consumer.
func TestRunCountsBacklogItCannotDrainInTime(t *testing.T) {
	const n = 400
	el := newEmitOrderEventLoop(t)
	el.stopDrainBudget = 50 * time.Millisecond
	rawCh := filledRawChannel(syncPairStream(t, 0, n))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var emitted int
	el.SetPrintCallback(func(ep *event.Pair) {
		emitted++
		time.Sleep(10 * time.Millisecond) // 400 pairs would take 4s
		ep.Recycle()
	})
	var warnings []string
	el.SetWarningCallback(func(msg string) { warnings = append(warnings, msg) })

	start := time.Now()
	el.run(ctx, rawCh)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("run took %v with a %v budget; the stop waited for the slow consumer", elapsed, el.stopDrainBudget)
	}
	if el.numDiscardedAtStop == 0 || emitted == 0 {
		t.Fatalf("emitted %d, discarded %d; want a partial drain", emitted, el.numDiscardedAtStop)
	}
	if got := el.numTracepoints + el.numDiscardedAtStop; got != 2*n {
		t.Fatalf("tracepoints %d + discarded %d = %d, want the backlog of %d", el.numTracepoints, el.numDiscardedAtStop, got, 2*n)
	}
	if len(rawCh) != int(el.numDiscardedAtStop) {
		t.Fatalf("%d records left in rawCh, numDiscardedAtStop = %d", len(rawCh), el.numDiscardedAtStop)
	}
	requireEveryProducedPairEmitted(t, el, emitted, int(el.numTracepoints))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "discarded at stop") {
		t.Fatalf("warnings = %q, want one about the discarded records", warnings)
	}
	if stats := el.stats(); !strings.Contains(stats, "records discarded at stop:") {
		t.Fatalf("stats do not report the discarded records:\n%s", stats)
	}
}

// TestDrainBacklogAtStopSkipsAfterOutputFailure pins the failed-output branch:
// rows of a dead stdout have nowhere to go, so the drain decodes nothing and
// the whole backlog is reported as discarded rather than silently dropped.
func TestDrainBacklogAtStopSkipsAfterOutputFailure(t *testing.T) {
	const n = 20
	el, pairs := newDrainHarness(t)
	el.outputErr = errors.New("broken pipe")
	rawCh := filledRawChannel(syncPairStream(t, 0, n))

	var emitted int
	el.SetPrintCallback(func(ep *event.Pair) {
		emitted++
		ep.Recycle()
	})
	var warnings []string
	el.SetWarningCallback(func(msg string) { warnings = append(warnings, msg) })

	el.drainBacklogAtStop(rawCh, pairs, nil)

	if emitted != 0 || el.numTracepoints != 0 {
		t.Fatalf("decoded %d records, emitted %d pairs after the output failed", el.numTracepoints, emitted)
	}
	if el.numDiscardedAtStop != 2*n {
		t.Fatalf("numDiscardedAtStop = %d, want %d", el.numDiscardedAtStop, 2*n)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "output had already failed") {
		t.Fatalf("warnings = %q, want one naming the failed output", warnings)
	}
}

// TestDrainBacklogAtStopWithEmptyChannelIsQuiet is the negative: nothing
// buffered means nothing discarded and no warning.
func TestDrainBacklogAtStopWithEmptyChannelIsQuiet(t *testing.T) {
	el, pairs := newDrainHarness(t)
	var warnings []string
	el.SetWarningCallback(func(msg string) { warnings = append(warnings, msg) })

	el.drainBacklogAtStop(make(chan []byte, 4), pairs, nil)

	if el.numDiscardedAtStop != 0 || len(warnings) != 0 || el.numTracepoints != 0 {
		t.Fatalf("discarded %d, warnings %q, tracepoints %d; want all quiet", el.numDiscardedAtStop, warnings, el.numTracepoints)
	}
}
