package internal

import (
	"errors"
	"testing"
	"time"

	"ior/internal/event"
)

// Task f23, the bounds of the stop's snapshot (backlogAtStop): how long it
// waits for a poller that does not come to rest, what that wait costs the
// drain, and what it does about a ring whose count ended at a busy record.

// scriptedRing is a ring without a poller: it is never empty, and each walk
// answers with the next entry of walks (the last one from then on).
type scriptedRing struct {
	walks  []ringbufUnread
	walked int
}

func (r *scriptedRing) Positions() (ringbufPositions, error) {
	return ringbufPositions{producer: fakeRingRecordSpan}, nil
}

func (r *scriptedRing) Unread() (ringbufUnread, error) {
	answer := r.walks[min(r.walked, len(r.walks)-1)]
	r.walked++
	return answer, nil
}

// stopReturnsWithin is how long a stop may take in these tests whatever the
// poller does: stopSettleBudget (50 ms) and the scheduling of a busy host
// under -race. It is a figure of its own, not derived from the budget, so
// that a budget grown past it fails here.
const stopReturnsWithin = time.Second

// drainWithin runs the stop-time drain and fails the test when it has not
// returned within limit; it reports how long the drain took.
func drainWithin(t *testing.T, el *eventLoop, rawCh chan []byte, pairs chan *event.Pair, limit time.Duration) time.Duration {
	t.Helper()
	done := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		el.drainBacklogAtStop(rawCh, pairs, nil)
		done <- time.Since(start)
	}()
	select {
	case took := <-done:
		return took
	case <-time.After(limit):
		t.Fatalf("the stop has not returned after %v", limit)
		return 0
	}
}

// halfFullRawChannel returns a rawCh that holds the stream and has room for
// as much again: a poller that is alive would go on filling it.
func halfFullRawChannel(stream [][]byte) chan []byte {
	rawCh := make(chan []byte, 2*len(stream))
	for _, raw := range stream {
		rawCh <- raw
	}
	return rawCh
}

// TestStopGivesUpOnAPollerThatNeverRests: records in the ring and room in
// rawCh, for good - the poller died, or the host starves it. The stop must
// not wait for it beyond stopSettleBudget; it then drains what rawCh holds
// and reports the ring as it is.
func TestStopGivesUpOnAPollerThatNeverRests(t *testing.T) {
	const pairsBuffered, left = 8, 1234
	el, pairs := newDrainHarness(t)
	ring := &scriptedRing{walks: []ringbufUnread{{records: left, bytes: left * fakeRingRecordSpan}}}
	el.ringUnread = ring
	rawCh := halfFullRawChannel(syncPairStream(t, 0, pairsBuffered))

	took := drainWithin(t, el, rawCh, pairs, stopReturnsWithin)

	if took < stopSettleBudget {
		t.Fatalf("the stop took %v: it did not give the poller its %v to rest", took, stopSettleBudget)
	}
	requireStopAccounting(t, el, 2*pairsBuffered+left, 2*pairsBuffered, 0, left)
	if len(rawCh) != 0 || ring.walked != 1 {
		t.Fatalf("rawCh holds %d records, the ring was walked %d times; want a drained channel and one walk", len(rawCh), ring.walked)
	}
}

// TestStopDrainBudgetStartsAfterTheSnapshot: the wait for the poller is not
// taken from the drain's budget. With a budget shorter than that wait, a
// deadline set before the snapshot would have passed before the first record
// was decoded, and the whole backlog would be "discarded at stop".
func TestStopDrainBudgetStartsAfterTheSnapshot(t *testing.T) {
	const pairsBuffered, left = 8, 99
	el, pairs := newDrainHarness(t)
	el.stopDrainBudget = stopSettleBudget / 2
	el.ringUnread = &scriptedRing{walks: []ringbufUnread{{records: left, bytes: left * fakeRingRecordSpan}}}
	rawCh := halfFullRawChannel(syncPairStream(t, 0, pairsBuffered))

	drainWithin(t, el, rawCh, pairs, stopReturnsWithin)

	requireStopAccounting(t, el, 2*pairsBuffered+left, 2*pairsBuffered, 0, left)
}

// TestStopWalksTheRingAgainBehindABusyRecord: the count ended at a record a
// CPU was still writing, so the records other CPUs committed behind it are
// not in it. The poller delivers them once the busy one is committed, so the
// stop counts again a moment later instead of leaving them out of every
// figure. rawCh is full, as with a poller blocked on it.
func TestStopWalksTheRingAgainBehindABusyRecord(t *testing.T) {
	const pairsBuffered = 4
	el, pairs := newDrainHarness(t)
	ring := &scriptedRing{walks: []ringbufUnread{
		{records: 3, bytes: 3 * fakeRingRecordSpan, busy: true},
		{records: 5, bytes: 5 * fakeRingRecordSpan},
	}}
	el.ringUnread = ring

	el.drainBacklogAtStop(filledRawChannel(syncPairStream(t, 0, pairsBuffered)), pairs, nil)

	requireStopAccounting(t, el, 2*pairsBuffered+5, 2*pairsBuffered, 0, 5)
	if ring.walked != 2 {
		t.Fatalf("the ring was walked %d times, want twice: once more behind the busy record", ring.walked)
	}
}

// TestStopCountsWhatItCanBehindARecordThatStaysBusy: a record that is never
// committed must not hold the stop. Past stopSettleBudget the count is taken
// as it is.
func TestStopCountsWhatItCanBehindARecordThatStaysBusy(t *testing.T) {
	const pairsBuffered = 4
	el, pairs := newDrainHarness(t)
	ring := &scriptedRing{walks: []ringbufUnread{{records: 3, bytes: 3 * fakeRingRecordSpan, busy: true}}}
	el.ringUnread = ring

	took := drainWithin(t, el, filledRawChannel(syncPairStream(t, 0, pairsBuffered)), pairs, stopReturnsWithin)

	requireStopAccounting(t, el, 2*pairsBuffered+3, 2*pairsBuffered, 0, 3)
	if ring.walked < 2 || took < stopSettleBudget {
		t.Fatalf("walked %d times in %v; want the ring counted again until the %v were up", ring.walked, took, stopSettleBudget)
	}
}

// TestStopMarksARecordingLowerBoundWhenRecordsWereLeft: a TUI recording fed
// by the stopping session lacks the rows of every record the stop did not
// decode, discarded from rawCh or left in the kernel ring, so its totals are
// a lower bound. A stop that decoded everything leaves them exact.
func TestStopMarksARecordingLowerBoundWhenRecordsWereLeft(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(el *eventLoop)
		want  int
	}{
		{"everything decoded", func(*eventLoop) {}, 0},
		{"empty ring", func(el *eventLoop) { el.ringUnread = fakeRingUnread{} }, 0},
		{"left in the kernel ring", func(el *eventLoop) {
			el.ringUnread = fakeRingUnread{unread: ringbufUnread{records: 7, bytes: 7 * fakeRingRecordSpan}}
		}, 1},
		{"discarded at stop", func(el *eventLoop) { el.outputErr = errors.New("broken pipe") }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el, pairs := newDrainHarness(t)
			counter := &samplingCounterStub{}
			el.SetRecordingSamplingCounter(counter)
			tc.setup(el)
			el.drainBacklogAtStop(filledRawChannel(syncPairStream(t, 0, 4)), pairs, nil)
			if counter.lowerBound != tc.want {
				t.Fatalf("lower-bound marks = %d, want %d", counter.lowerBound, tc.want)
			}
		})
	}
}
