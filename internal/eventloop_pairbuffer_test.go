package internal

import (
	"context"
	"testing"
	"time"

	"ior/internal/benchutil"
	appconfig "ior/internal/config"
	"ior/internal/event"
	"ior/internal/types"
)

// The tests in this file pin the contract of the buffered pair channel that
// events() hands to run(): pairs arrive in production order, the buffer is
// bounded (backpressure still reaches rawCh), and no pair that was already
// produced is lost when decoding stops on ctx cancellation or a closed rawCh.

const (
	pairBufferTestTid       = 4242
	pairBufferTestTimeStep  = 1000
	pairBufferTestStartTime = 1_000_000
	pairBufferTestWait      = 5 * time.Second
)

// newAsyncPairBufferEventLoop builds an event loop that uses the production
// two-goroutine path. mustNewEventLoop forces synchronous processing for
// *testing.T, which would bypass events() entirely.
func newAsyncPairBufferEventLoop(t *testing.T) *eventLoop {
	t.Helper()
	el, err := newEventLoop(eventLoopConfig{})
	if err != nil {
		t.Fatalf("newEventLoop() error = %v", err)
	}
	el.initRawHandlers()
	// A cached comm keeps the enter path off procfs for the synthetic tid.
	el.setCachedComm(pairBufferTestTid, "pairbuf")
	return el
}

// pairBufferTestTime is the enter timestamp of the i-th generated pair; the
// tests identify pairs (and check their order) by it.
func pairBufferTestTime(i int) uint64 {
	return pairBufferTestStartTime + uint64(i)*pairBufferTestTimeStep
}

// syncPairStream returns n enter/exit sync pairs for one tid, in order.
func syncPairStream(t *testing.T, n int) [][]byte {
	t.Helper()
	gen := benchutil.NewEventGenerator()
	stream := make([][]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		enter, exit, err := gen.NullPair(pairBufferTestTime(i), pairBufferTestTid, pairBufferTestTid,
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

// waitForBufferedPairs polls until out holds want pairs. It never receives,
// so every pair it waits for is still sitting in the buffer afterwards.
func waitForBufferedPairs(t *testing.T, out <-chan *event.Pair, want int) {
	t.Helper()
	deadline := time.Now().Add(pairBufferTestWait)
	for len(out) < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d buffered pairs, have %d", want, len(out))
		}
		time.Sleep(time.Millisecond)
	}
}

// collectUntilClosed receives from out until it is closed and returns the
// enter timestamps of the received pairs, recycling each pair.
func collectUntilClosed(t *testing.T, out <-chan *event.Pair) []uint64 {
	t.Helper()
	var times []uint64
	timeout := time.After(pairBufferTestWait)
	for {
		select {
		case ep, ok := <-out:
			if !ok {
				return times
			}
			times = append(times, ep.EnterEv.GetTime())
			ep.Recycle()
		case <-timeout:
			t.Fatalf("timed out waiting for the pair channel to close after %d pairs", len(times))
		}
	}
}

// requireOrderedPairs asserts that times holds exactly the enter timestamps
// of pairs 0..want-1, in production order.
func requireOrderedPairs(t *testing.T, times []uint64, want int) {
	t.Helper()
	if len(times) != want {
		t.Fatalf("received %d pairs, want %d", len(times), want)
	}
	for i, got := range times {
		if exp := pairBufferTestTime(i); got != exp {
			t.Fatalf("pair %d has enter time %d, want %d (order broken)", i, got, exp)
		}
	}
}

func TestEventsPairChannelIsBuffered(t *testing.T) {
	el := newAsyncPairBufferEventLoop(t)
	ctx, cancel := context.WithCancel(context.Background())
	out := el.events(ctx, make(chan []byte))
	cancel()
	if got := cap(out); got != appconfig.PairChannelBufferSize {
		t.Fatalf("pair channel capacity = %d, want %d", got, appconfig.PairChannelBufferSize)
	}
	collectUntilClosed(t, out)
}

// TestEventsEmitsBufferedPairsAfterCancel is the shutdown guarantee: pairs
// the decode goroutine already produced into the buffer must still reach the
// consumer after ctx is cancelled.
func TestEventsEmitsBufferedPairsAfterCancel(t *testing.T) {
	const n = 16
	el := newAsyncPairBufferEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, n))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := el.events(ctx, rawCh)
	waitForBufferedPairs(t, out, n)
	cancel()

	requireOrderedPairs(t, collectUntilClosed(t, out), n)
}

// TestEventsEmitsBufferedPairsAfterRawChannelClose covers the other stop
// path: rawCh closing (ring buffer torn down) while pairs are still buffered.
func TestEventsEmitsBufferedPairsAfterRawChannelClose(t *testing.T) {
	const n = 16
	el := newAsyncPairBufferEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, n))
	close(rawCh)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := el.events(ctx, rawCh)
	waitForBufferedPairs(t, out, n)

	requireOrderedPairs(t, collectUntilClosed(t, out), n)
}

// TestEventsBoundsPairsInFlight is the backpressure guarantee: with nobody
// receiving, decoding stalls once the pair buffer is full instead of draining
// rawCh, and every pair still arrives in order once the consumer catches up.
func TestEventsBoundsPairsInFlight(t *testing.T) {
	const extraPairs = 10
	n := appconfig.PairChannelBufferSize + extraPairs
	el := newAsyncPairBufferEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, n))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := el.events(ctx, rawCh)
	waitForBufferedPairs(t, out, cap(out))
	// Give an unbounded producer ample time to run ahead; a bounded one is
	// parked on the send of pair cap(out)+1.
	time.Sleep(20 * time.Millisecond)
	if got := len(out); got != cap(out) {
		t.Fatalf("pair buffer holds %d pairs, want exactly its capacity %d", got, cap(out))
	}
	// The producer may hold one decoded pair (two raw records) it cannot send.
	if minLeft := 2*extraPairs - 2; len(rawCh) < minLeft {
		t.Fatalf("rawCh drained to %d records while the pair buffer was full, want >= %d", len(rawCh), minLeft)
	}

	close(rawCh)
	requireOrderedPairs(t, collectUntilClosed(t, out), n)
}

// TestEventsKeepsOrderAroundRecoveredPanic checks that a handler panic
// neither drops nor reorders the pairs produced around it.
func TestEventsKeepsOrderAroundRecoveredPanic(t *testing.T) {
	const n = 8
	el := newAsyncPairBufferEventLoop(t)
	warnings := make(chan string, 4)
	el.warningCb = func(message string) { warnings <- message }
	el.rawHandlers[types.ENTER_OPEN_EVENT] = func(_ []byte, _ chan<- *event.Pair) {
		panic("injected test panic")
	}

	stream := syncPairStream(t, n)
	// Inject the panicking record between two complete pairs.
	mid := n // stream index after pair n/2-1's exit
	withPanic := append(append(append([][]byte{}, stream[:mid]...), []byte{byte(types.ENTER_OPEN_EVENT)}), stream[mid:]...)
	rawCh := filledRawChannel(withPanic)
	close(rawCh)

	out := el.events(context.Background(), rawCh)
	requireOrderedPairs(t, collectUntilClosed(t, out), n)
	select {
	case <-warnings:
	default:
		t.Fatal("expected a panic-recovery warning")
	}
}

// TestRunAsyncEmitsEveryPairProducedBeforeCancel drives run() itself: the
// consumer cancels ctx on the very first pair, so the decode goroutine stops
// with pairs still buffered. Every pair it produced (numSyscalls) must be
// emitted and counted (numSyscallsAfterFilter), in order.
func TestRunAsyncEmitsEveryPairProducedBeforeCancel(t *testing.T) {
	n := 3 * appconfig.PairChannelBufferSize
	el := newAsyncPairBufferEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, n))
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

	if el.numSyscalls == 0 {
		t.Fatal("no pair was produced")
	}
	if uint(len(times)) != el.numSyscalls {
		t.Fatalf("emitted %d pairs, but %d were produced", len(times), el.numSyscalls)
	}
	if el.numSyscallsAfterFilter != el.numSyscalls {
		t.Fatalf("numSyscallsAfterFilter = %d, want %d", el.numSyscallsAfterFilter, el.numSyscalls)
	}
	requireOrderedPairs(t, times, len(times))
}

// TestRunAsyncEmitsAllPairsOnRawChannelClose drives run() through more pairs
// than the buffer holds and checks count, accounting and order.
func TestRunAsyncEmitsAllPairsOnRawChannelClose(t *testing.T) {
	n := 3 * appconfig.PairChannelBufferSize
	el := newAsyncPairBufferEventLoop(t)
	rawCh := filledRawChannel(syncPairStream(t, n))
	close(rawCh)

	var times []uint64
	el.SetPrintCallback(func(ep *event.Pair) {
		times = append(times, ep.EnterEv.GetTime())
		ep.Recycle()
	})

	el.run(context.Background(), rawCh)

	requireOrderedPairs(t, times, n)
	if el.numSyscallsAfterFilter != uint(n) {
		t.Fatalf("numSyscallsAfterFilter = %d, want %d", el.numSyscallsAfterFilter, n)
	}
}
