package internal

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"
)

// Task f23: every record the kernel produced before the stop must be in
// exactly one end-of-run figure - decoded ("tracepoints"), discarded at stop,
// or left in the kernel ring buffer. The tests run the stop against a ring
// whose poller is still alive, as libbpfgo's is until RingBuffer.Stop: it
// refills rawCh as fast as the drain makes room.

// fakeRingPoller stands in for the kernel ring buffer and libbpfgo's poller.
// Like the real one it handles one record at a time: it sends the record to
// rawCh, blocking while that is full, and advances the consumer position only
// after the send returned. Unread answers from that position, as
// kernelRingUnread does from the ring's own bookkeeping.
type fakeRingPoller struct {
	stream [][]byte
	rawCh  chan []byte
	// consumed is the consumer position, in records.
	consumed atomic.Uint64
	// holdSendAt and holdStoreAt (-1: never) make the poller wait for the
	// first Unread call before it sends that record, or before it advances
	// the consumer position behind it: the states a stop can find it in.
	// The first Unread returns only when a held advance has happened (stored
	// is closed), so the second look sees it however the poller is scheduled.
	holdSendAt, holdStoreAt int
	looked, stored          chan struct{}
	lookedOnce              sync.Once
	quit                    chan struct{}
}

// fakeRingRecordSpan is the size the fake ring gives every record.
const fakeRingRecordSpan = 64

// startFakeRingPoller starts a poller over stream that feeds a rawCh of the
// given capacity. It is stopped when the test ends.
func startFakeRingPoller(t *testing.T, stream [][]byte, capacity, holdSendAt, holdStoreAt int) *fakeRingPoller {
	t.Helper()
	r := &fakeRingPoller{
		stream:      stream,
		rawCh:       make(chan []byte, capacity),
		holdSendAt:  holdSendAt,
		holdStoreAt: holdStoreAt,
		looked:      make(chan struct{}),
		stored:      make(chan struct{}),
		quit:        make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.poll()
	}()
	t.Cleanup(func() {
		close(r.quit)
		<-done
	})
	return r
}

func (r *fakeRingPoller) poll() {
	for i, raw := range r.stream {
		if i == r.holdSendAt && !r.waitForLook() {
			return
		}
		select {
		case r.rawCh <- raw:
		case <-r.quit:
			return
		}
		if i != r.holdStoreAt {
			r.consumed.Add(1)
			continue
		}
		if !r.waitForLook() {
			return
		}
		r.consumed.Add(1)
		close(r.stored)
	}
}

// waitForLook blocks until the stop looked at the ring once; false: quit.
func (r *fakeRingPoller) waitForLook() bool {
	select {
	case <-r.looked:
		return true
	case <-r.quit:
		return false
	}
}

func (r *fakeRingPoller) Unread() (ringbufUnread, error) {
	consumed := r.consumed.Load()
	r.lookedOnce.Do(func() {
		close(r.looked)
		if r.holdStoreAt >= 0 {
			<-r.stored
		}
	})
	left := uint64(len(r.stream)) - consumed
	return ringbufUnread{records: left, bytes: left * fakeRingRecordSpan}, nil
}

// waitForBacklog waits until rawCh holds n records.
func (r *fakeRingPoller) waitForBacklog(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(r.rawCh) != n {
		if time.Now().After(deadline) {
			t.Fatalf("rawCh holds %d records, want %d", len(r.rawCh), n)
		}
		time.Sleep(100 * time.Microsecond)
	}
}

// waitForConsumed waits until the poller's consumer position is n records.
func (r *fakeRingPoller) waitForConsumed(t *testing.T, n uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.consumed.Load() != n {
		if time.Now().After(deadline) {
			t.Fatalf("the poller consumed %d records, want %d", r.consumed.Load(), n)
		}
		time.Sleep(100 * time.Microsecond)
	}
}

// requireStopAccounting checks the three figures and that they add up to the
// records produced.
func requireStopAccounting(t *testing.T, el *eventLoop, produced, decoded, discarded, left uint) {
	t.Helper()
	if el.numTracepoints != decoded || el.numDiscardedAtStop != discarded || el.numLeftInKernelRing != left {
		t.Fatalf("tracepoints %d, discarded at stop %d, left in the ring %d; want %d, %d, %d",
			el.numTracepoints, el.numDiscardedAtStop, el.numLeftInKernelRing, decoded, discarded, left)
	}
	if sum := el.numTracepoints + el.numDiscardedAtStop + el.numLeftInKernelRing; sum != produced {
		t.Fatalf("the figures add up to %d of the %d records produced", sum, produced)
	}
}

// TestStopAccountsForAFullRawChannelRefilledDuringTheDrain is the reported
// case: the loop lags, rawCh is full at the stop and the poller is blocked on
// it. The drain decodes that channel's worth, and the poller refills rawCh
// behind it from the ring. Counting the ring after the drain left exactly one
// channel's worth (4096 records in production) in no figure at all.
func TestStopAccountsForAFullRawChannelRefilledDuringTheDrain(t *testing.T) {
	const pairsProduced, capacity = 500, 64
	el, pairs := newDrainHarness(t)
	ring := startFakeRingPoller(t, syncPairStream(t, 0, pairsProduced), capacity, -1, -1)
	el.ringUnread = ring
	ring.waitForBacklog(t, capacity)
	// Each pair the drain emits made room for two records; the drain goes on
	// only when the poller has moved them from the ring into rawCh, so the
	// refill is complete, on any schedule, when the drain ends.
	emitted := uint64(0)
	el.SetPrintCallback(func(ep *event.Pair) {
		emitted++
		ring.waitForConsumed(t, capacity+2*emitted)
		ep.Recycle()
	})

	el.drainBacklogAtStop(ring.rawCh, pairs, nil)

	requireStopAccounting(t, el, 2*pairsProduced, capacity, 0, 2*pairsProduced-capacity)
	if len(ring.rawCh) != capacity {
		t.Fatalf("rawCh holds %d records after the drain, want it refilled to %d", len(ring.rawCh), capacity)
	}
}

// TestStopWaitsForThePollerToAdvanceBehindItsLastSend catches the poller
// between the send that filled rawCh and the consumer position's advance: on
// the first look that record is in rawCh and still in the ring's count. The
// stop must look again, or it counts the record twice.
func TestStopWaitsForThePollerToAdvanceBehindItsLastSend(t *testing.T) {
	const pairsProduced, capacity = 100, 16
	el, pairs := newDrainHarness(t)
	ring := startFakeRingPoller(t, syncPairStream(t, 0, pairsProduced), capacity, -1, capacity-1)
	el.ringUnread = ring
	ring.waitForBacklog(t, capacity)

	el.drainBacklogAtStop(ring.rawCh, pairs, nil)

	requireStopAccounting(t, el, 2*pairsProduced, capacity, 0, 2*pairsProduced-capacity)
}

// TestStopDecodesWhatThePollerStillDelivers is the run that kept up: the ring
// holds a few records the poller has not handed on yet. The stop waits for
// them instead of reporting them as left behind, and decodes them all.
func TestStopDecodesWhatThePollerStillDelivers(t *testing.T) {
	const pairsProduced, capacity, early = 20, 64, 10
	el, pairs := newDrainHarness(t)
	var warnings []string
	el.SetWarningCallback(func(msg string) { warnings = append(warnings, msg) })
	ring := startFakeRingPoller(t, syncPairStream(t, 0, pairsProduced), capacity, early, -1)
	el.ringUnread = ring
	ring.waitForBacklog(t, early)

	el.drainBacklogAtStop(ring.rawCh, pairs, nil)

	requireStopAccounting(t, el, 2*pairsProduced, 2*pairsProduced, 0, 0)
	if len(warnings) != 0 || el.leftInKernelRingStatLine() != "" || el.discardedAtStopStatLine() != "" {
		t.Fatalf("a complete stop reported a loss: warnings %q", warnings)
	}
}

// TestStopAccountsForAFullRawChannelItCannotDecode: with the output already
// failed nothing is decoded, so the full rawCh is discarded and the ring
// behind it left - each record in one figure.
func TestStopAccountsForAFullRawChannelItCannotDecode(t *testing.T) {
	const pairsProduced, capacity = 100, 16
	el, pairs := newDrainHarness(t)
	el.outputErr = errors.New("broken pipe")
	ring := startFakeRingPoller(t, syncPairStream(t, 0, pairsProduced), capacity, -1, -1)
	el.ringUnread = ring
	ring.waitForBacklog(t, capacity)

	el.drainBacklogAtStop(ring.rawCh, pairs, nil)

	requireStopAccounting(t, el, 2*pairsProduced, 0, capacity, 2*pairsProduced-capacity)
}

// TestRunAccountsForEveryRecordWhenStoppedMidStream stops the whole loop from
// inside the stream, as a target's exit does, with the poller running. Where
// the stop finds the poller varies from run to run; the sum must not.
func TestRunAccountsForEveryRecordWhenStoppedMidStream(t *testing.T) {
	const pairsProduced, capacity, stopAfter = 2000, 32, 300
	el := newEmitOrderEventLoop(t)
	ring := startFakeRingPoller(t, syncPairStream(t, 0, pairsProduced), capacity, -1, -1)
	el.ringUnread = ring
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emitted := 0
	el.SetPrintCallback(func(ep *event.Pair) {
		if emitted++; emitted == stopAfter {
			cancel()
		}
		ep.Recycle()
	})

	el.run(ctx, ring.rawCh)

	sum := el.numTracepoints + el.numDiscardedAtStop + el.numLeftInKernelRing
	if sum != 2*pairsProduced || el.numLeftInKernelRing == 0 {
		t.Fatalf("tracepoints %d + discarded %d + left in the ring %d = %d, want the %d records produced with some left",
			el.numTracepoints, el.numDiscardedAtStop, el.numLeftInKernelRing, sum, 2*pairsProduced)
	}
}
