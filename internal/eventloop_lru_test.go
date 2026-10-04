package internal

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/file"
	"ior/internal/types"
)

// TestPairTrackerPrevTimesEvictsOldestEntries verifies the per-TID
// DurationToPrev metadata is LRU-capped like the pending enters, so
// thread-churning traces cannot grow prevTimes without bound. It also locks
// in that pruning prevTimes leaves the pending enters map untouched, despite
// both sharing the same monotonic age counter.
func TestPairTrackerPrevTimesEvictsOldestEntries(t *testing.T) {
	tracker := pairTracker{maxSize: 2}

	// Seed a pending enter first: its age must survive prevTimes pruning.
	enterEv, _ := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	tracker.set(&enterEv)
	seededAge := tracker.enterAges[defaultTid]

	tracker.setPrevTime(defaultTid, 100)
	tracker.setPrevTime(defaultTid+1, 200)
	tracker.setPrevTime(defaultTid+2, 300)

	if _, ok := tracker.prevTimes[defaultTid]; ok {
		t.Fatalf("expected oldest prevTimes entry to be evicted")
	}
	if got := tracker.prevTime(defaultTid); got != 0 {
		t.Fatalf("evicted prevTimes entry must read as zero, got %d", got)
	}
	if got := tracker.prevTime(defaultTid + 1); got != 200 {
		t.Fatalf("expected newer prevTimes entry to be retained, got %d", got)
	}
	if got := tracker.prevTime(defaultTid + 2); got != 300 {
		t.Fatalf("expected newest prevTimes entry to be retained, got %d", got)
	}
	if got := len(tracker.prevTimeAges); got != 2 {
		t.Fatalf("prevTimes LRU metadata size = %d, want 2", got)
	}
	if got := len(tracker.enters); got != 1 {
		t.Fatalf("prevTimes pruning must not touch the pending enters map, got %d entries", got)
	}
	if got := tracker.enterAges[defaultTid]; got != seededAge {
		t.Fatalf("pending enter age = %d, want unchanged %d", got, seededAge)
	}
	for _, pair := range tracker.enters {
		pair.Recycle()
	}
}

// TestPairTrackerPrevTimesRefreshesOnUpdate verifies a repeated setPrevTime for
// the same TID refreshes its LRU age, so active threads are retained.
func TestPairTrackerPrevTimesRefreshesOnUpdate(t *testing.T) {
	tracker := pairTracker{maxSize: 2}

	tracker.setPrevTime(defaultTid, 100)
	tracker.setPrevTime(defaultTid+1, 200)
	tracker.setPrevTime(defaultTid, 150) // refresh: becomes the most recent
	tracker.setPrevTime(defaultTid+2, 300)

	if _, ok := tracker.prevTimes[defaultTid]; !ok {
		t.Fatalf("expected refreshed prevTimes entry to be retained")
	}
	if _, ok := tracker.prevTimes[defaultTid+1]; ok {
		t.Fatalf("expected stale prevTimes entry to be evicted")
	}
	if got := tracker.prevTime(defaultTid); got != 150 {
		t.Fatalf("expected refreshed value to be stored, got %d", got)
	}
}

// TestCommResolverSetCachedEvictsOldestEntries verifies the comm cache is
// LRU-capped so resolved comms cannot grow without bound.
func TestCommResolverSetCachedEvictsOldestEntries(t *testing.T) {
	resolver := newCommResolver(nil)
	defer resolver.shutdown()
	resolver.maxComms = 2

	resolver.setCached(defaultTid, "comm-one")
	resolver.setCached(defaultTid+1, "comm-two")
	resolver.setCached(defaultTid+2, "comm-three")

	if _, ok := resolver.cached(defaultTid); ok {
		t.Fatalf("expected oldest comm to be evicted")
	}
	if got, ok := resolver.cached(defaultTid + 1); !ok || got != "comm-two" {
		t.Fatalf("expected newer comm to be retained, got %q (ok=%v)", got, ok)
	}
	if got, ok := resolver.cached(defaultTid + 2); !ok || got != "comm-three" {
		t.Fatalf("expected newest comm to be retained, got %q (ok=%v)", got, ok)
	}
	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	if got := len(resolver.commAges); got != 2 {
		t.Fatalf("comm LRU metadata size = %d, want 2", got)
	}
}

// TestCommResolverCachedRefreshesLRU verifies reads refresh the LRU age so
// active TIDs are retained over one-shot lookups.
func TestCommResolverCachedRefreshesLRU(t *testing.T) {
	resolver := newCommResolver(nil)
	defer resolver.shutdown()
	resolver.maxComms = 2

	resolver.setCached(defaultTid, "comm-one")
	resolver.setCached(defaultTid+1, "comm-two")
	if _, ok := resolver.cached(defaultTid); !ok {
		t.Fatalf("expected cached comm for tid %d", defaultTid)
	}
	resolver.setCached(defaultTid+2, "comm-three")

	if _, ok := resolver.cached(defaultTid); !ok {
		t.Fatalf("expected recently used comm to be retained")
	}
	if _, ok := resolver.cached(defaultTid + 1); ok {
		t.Fatalf("expected least recently used comm to be evicted")
	}
	if _, ok := resolver.cached(defaultTid + 2); !ok {
		t.Fatalf("expected newest comm to be retained")
	}
}

// TestCommResolverLookupWorkerWritePrunesToLimit verifies the worker-side
// cache write goes through the same LRU pruning as setCached.
func TestCommResolverLookupWorkerWritePrunesToLimit(t *testing.T) {
	resolver := newCommResolver(nil)
	defer resolver.shutdown()
	resolver.lookupWorkers = 1
	resolver.maxComms = 2
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		return fmt.Sprintf("comm-%d", tid), nil
	}

	for i := uint32(1); i <= 4; i++ {
		resolver.queueLookup(i)
	}

	waitForCondition(t, 2*time.Second, "expected comms to be pruned to the limit", func() bool {
		resolver.mu.RLock()
		defer resolver.mu.RUnlock()
		return len(resolver.comms) == 2 && pendingCount(resolver) == 0
	})

	if _, ok := resolver.cached(1); ok {
		t.Fatalf("expected oldest resolved comm to be evicted")
	}
	if _, ok := resolver.cached(2); ok {
		t.Fatalf("expected second-oldest resolved comm to be evicted")
	}
	if _, ok := resolver.cached(3); !ok {
		t.Fatalf("expected newer resolved comm to be retained")
	}
	if _, ok := resolver.cached(4); !ok {
		t.Fatalf("expected newest resolved comm to be retained")
	}
}

// recycleCountingEvent is a minimal event.Event stub whose Recycle increments
// a counter, so tests can assert a dropped event returns to its pool per the
// EventLifecycle contract.
type recycleCountingEvent struct {
	tid          uint32
	recycleCount *int32
}

func (e *recycleCountingEvent) String() string {
	return fmt.Sprintf("recycleCountingEvent(tid=%d)", e.tid)
}

func (e *recycleCountingEvent) GetTraceId() types.TraceId { return types.SYS_ENTER_OPEN - 1 }
func (e *recycleCountingEvent) GetPid() uint32            { return defaultPid }
func (e *recycleCountingEvent) GetTid() uint32            { return e.tid }
func (e *recycleCountingEvent) GetTime() uint64           { return 0 }
func (e *recycleCountingEvent) Equals(other any) bool     { return false }
func (e *recycleCountingEvent) Recycle()                  { atomic.AddInt32(e.recycleCount, 1) }

// TestTracepointEnteredRetainsFilteredEnterEvent verifies the happy path is
// unchanged: an enter event with a cached comm is stored, not recycled.
func TestTracepointEnteredRetainsFilteredEnterEvent(t *testing.T) {
	el := &eventLoop{
		pairs:        newPairTracker(),
		fdTracker:    newFDTracker(make(map[uint64]file.File)),
		commResolver: newHermeticCommResolver(),
		cfg:          eventLoopConfig{},
		done:         make(chan struct{}),
	}
	defer el.commResolver.shutdown()
	el.SetFilter(testFilter("nginx", ""))
	el.setCachedComm(defaultTid, "nginx")

	var recycles int32
	el.tracepointEntered(&recycleCountingEvent{tid: defaultTid, recycleCount: &recycles})

	if got := atomic.LoadInt32(&recycles); got != 0 {
		t.Fatalf("retained enter event must not be recycled, got %d recycles", got)
	}
	pair, ok := el.pairs.consume(defaultTid)
	if !ok {
		t.Fatalf("expected the enter event to be stored as pending pair")
	}
	pair.Recycle()
}
