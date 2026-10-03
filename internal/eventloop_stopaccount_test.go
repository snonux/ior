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
// after the send returned. Positions and Unread answer from that position, as
// kernelRingUnread does from the ring's own bookkeeping.
type fakeRingPoller struct {
	stream [][]byte
	rawCh  chan []byte
	// consumed is the consumer position, in records.
	consumed atomic.Uint64
	// holdSendAt (-1: never) makes the poller wait for the stop's first look
	// at the positions before it sends that record. holdStoreAt (-1: never)
	// makes it wait for the second look before it advances the consumer
	// position behind that record, and that look returns only when the
	// advance has happened (stored is closed): a stop that counts the ring
	// after one look finds the record still in it, one that looks twice
	// finds it gone, however the poller is scheduled.
	holdSendAt, holdStoreAt   int
	looked, lookedTwice       chan struct{}
	stored                    chan struct{}
	lookedOnce, lookedTwiceDo sync.Once
	looks                     atomic.Int32
	// walks counts the Unread calls: the walks over the ring's records.
	walks atomic.Int32
	quit  chan struct{}
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
		lookedTwice: make(chan struct{}),
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
		if i == r.holdSendAt && !r.waitFor(r.looked) {
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
		if !r.waitFor(r.lookedTwice) {
			return
		}
		r.consumed.Add(1)
		close(r.stored)
	}
}

// waitFor blocks until the stop has looked at the ring as often as look
// stands for; false: quit.
func (r *fakeRingPoller) waitFor(look <-chan struct{}) bool {
	select {
	case <-look:
		return true
	case <-r.quit:
		return false
	}
}

// Positions is the stop's look at the ring: the positions as they are when
// it is called, and the release of a poller held for that look.
func (r *fakeRingPoller) Positions() (ringbufPositions, error) {
	consumed := r.consumed.Load()
	if r.looks.Add(1) == 1 {
		r.lookedOnce.Do(func() { close(r.looked) })
	} else {
		r.lookedTwiceDo.Do(func() { close(r.lookedTwice) })
		if r.holdStoreAt >= 0 {
			<-r.stored
			consumed = r.consumed.Load()
		}
	}
	return ringbufPositions{
		consumer: consumed * fakeRingRecordSpan,
		producer: uint64(len(r.stream)) * fakeRingRecordSpan,
	}, nil
}

// Unread counts the records behind the consumer position.
func (r *fakeRingPoller) Unread() (ringbufUnread, error) {
	r.walks.Add(1)
	left := uint64(len(r.stream)) - r.consumed.Load()
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
	// The poller is waited for on the positions alone; the records are
	// counted in one walk, whose cost grows with the ring.
	if walks := ring.walks.Load(); walks != 1 {
		t.Fatalf("the stop walked the ring %d times, want once", walks)
	}
}

// TestStopWaitsForThePollerToAdvanceBehindItsLastSend catches the poller
// between the send that filled rawCh and the consumer position's advance:
// until the stop's second look that record is in rawCh and still in the
// ring's count. The stop must look again before it counts the ring, or it
// counts the record twice.
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
	if walks := ring.walks.Load(); walks != 0 {
		t.Fatalf("the stop walked the ring %d times, want none: it was empty", walks)
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
