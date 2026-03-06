package internal

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCommResolverQueueLookupRespectsWorkerLimit(t *testing.T) {
	const workers = 2
	const lookups = 6

	started := make(chan struct{}, lookups)
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(lookups)

	var running int32
	var maxRunning int32

	resolver := newCommResolver(nil)
	resolver.lookupWorkers = workers
	resolver.lookupQueue = make(chan uint32, lookups)
	resolver.resolveFn = func(tid uint32) string {
		current := atomic.AddInt32(&running, 1)
		setMaxInt32(&maxRunning, current)
		started <- struct{}{}
		<-release
		atomic.AddInt32(&running, -1)
		wg.Done()
		return fmt.Sprintf("comm-%d", tid)
	}

	for i := 1; i <= lookups; i++ {
		resolver.queueLookup(uint32(i))
	}

	waitForStarts(t, started, workers, 2*time.Second)
	select {
	case <-started:
		t.Fatalf("expected at most %d concurrent lookups", workers)
	case <-time.After(75 * time.Millisecond):
	}

	close(release)
	waitForWaitGroup(t, &wg, 2*time.Second)
	waitForCondition(t, 2*time.Second, "expected all queued tids to be cached", func() bool {
		for i := 1; i <= lookups; i++ {
			if _, ok := resolver.cached(uint32(i)); !ok {
				return false
			}
		}
		return pendingCount(resolver) == 0
	})

	if got := atomic.LoadInt32(&maxRunning); got > workers {
		t.Fatalf("expected max concurrent lookups <= %d, got %d", workers, got)
	}

	for i := 1; i <= lookups; i++ {
		want := fmt.Sprintf("comm-%d", i)
		got, ok := resolver.cached(uint32(i))
		if !ok {
			t.Fatalf("expected cached comm for tid %d", i)
		}
		if got != want {
			t.Fatalf("expected tid %d comm %q, got %q", i, want, got)
		}
	}

	if pending := pendingCount(resolver); pending != 0 {
		t.Fatalf("expected no pending lookups after completion, got %d", pending)
	}
}

func TestCommResolverQueueLookupQueueFullClearsPending(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	resolver := newCommResolver(nil)
	resolver.lookupWorkers = 1
	resolver.lookupQueue = make(chan uint32, 1)
	resolver.resolveFn = func(tid uint32) string {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return fmt.Sprintf("comm-%d", tid)
	}

	const tid1 uint32 = 101
	const tid2 uint32 = 102
	const tid3 uint32 = 103

	resolver.queueLookup(tid1)
	waitForStarts(t, started, 1, 2*time.Second)

	resolver.queueLookup(tid2)
	resolver.queueLookup(tid3)

	if !hasPending(resolver, tid1) {
		t.Fatalf("expected tid %d to remain pending while worker is blocked", tid1)
	}
	if !hasPending(resolver, tid2) {
		t.Fatalf("expected tid %d to remain pending while queued", tid2)
	}
	if hasPending(resolver, tid3) {
		t.Fatalf("expected tid %d pending flag to be cleared when queue is full", tid3)
	}

	close(release)

	waitForCondition(t, 2*time.Second, "expected first two tids to resolve", func() bool {
		_, ok1 := resolver.cached(tid1)
		_, ok2 := resolver.cached(tid2)
		return ok1 && ok2
	})

	if _, ok := resolver.cached(tid3); ok {
		t.Fatalf("did not expect tid %d to resolve from the dropped queue request", tid3)
	}

	resolver.queueLookup(tid3)
	waitForCondition(t, 2*time.Second, "expected dropped tid to be retried successfully", func() bool {
		_, ok := resolver.cached(tid3)
		return ok
	})
}

func hasPending(r *commResolver, tid uint32) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.pending[tid]
	return ok
}

func pendingCount(r *commResolver) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.pending)
}

func setMaxInt32(target *int32, candidate int32) {
	for {
		current := atomic.LoadInt32(target)
		if candidate <= current {
			return
		}
		if atomic.CompareAndSwapInt32(target, current, candidate) {
			return
		}
	}
}

func waitForStarts(t *testing.T, ch <-chan struct{}, count int, timeout time.Duration) {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for i := 0; i < count; i++ {
		select {
		case <-ch:
		case <-timer.C:
			t.Fatalf("timed out waiting for %d resolver lookups to start", count)
		}
	}
}

func waitForWaitGroup(t *testing.T, wg *sync.WaitGroup, timeout time.Duration) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for resolver lookups to complete")
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, message string, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
