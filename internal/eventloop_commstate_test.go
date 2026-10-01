package internal

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
)

// commState runs several times per traced event (comm, cached,
// queueCommLookup, setCachedComm*), so its steady state must not allocate.
// It used to re-evaluate the method value e.notifyWarning on every call,
// which heap-allocates a closure and accounted for ~46% of all pipeline
// allocations. These tests pin the one-time wiring and its allocation cost.
//
// Every loop here is built around an injected resolver whose resolveFn is set
// before newEventLoop runs. newEventLoop seeds the comms of the test process
// and its parent synchronously; with the default procfs resolver an
// unreadable /proc/<pid>/comm would queue a lookup and start the lookup
// workers, which then race with the test's own resolver mutations and can
// report extra warnings. A resolveFn that answers every seed makes the
// constructor finish with no lookup queued and no worker running.

// seededComm is what the deterministic resolvers answer for every tid the
// test does not single out, including the constructor's pid/ppid seeds.
const seededComm = "seeded"

// newDeterministicLoop builds a loop around a fresh resolver whose lookups go
// through resolveFn instead of procfs, and checks that construction left no
// lookup behind (so no worker can be running).
func newDeterministicLoop(t *testing.T, resolveFn func(context.Context, uint32) (string, error)) (*eventLoop, *commResolver) {
	t.Helper()
	resolver := newCommResolver(nil)
	resolver.resolveFn = resolveFn
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(el.shutdownCommResolver)
	assertNoLookupQueued(t, resolver)
	return el, resolver
}

func seededResolveFn(context.Context, uint32) (string, error) { return seededComm, nil }

func assertNoLookupQueued(t *testing.T, resolver *commResolver) {
	t.Helper()
	resolver.mu.RLock()
	pending, queued := len(resolver.pending), len(resolver.lookupQueue)
	resolver.mu.RUnlock()
	if pending != 0 || queued != 0 {
		t.Fatalf("construction left lookups behind: pending=%d queued=%d", pending, queued)
	}
}

// TestCommStateWarmCacheDoesNotAllocate pins the fix: resolving a cached comm
// through the loop, and fetching the other per-event trackers, costs zero
// heap allocations.
func TestCommStateWarmCacheDoesNotAllocate(t *testing.T) {
	const tid = 4242
	el, _ := newDeterministicLoop(t, seededResolveFn)
	el.setCachedComm(tid, "warm")
	if got := el.comm(tid); got != "warm" {
		t.Fatalf("comm(%d) = %q, want %q", tid, got, "warm")
	}

	checks := []struct {
		name string
		fn   func()
	}{
		{"commState", func() { _ = el.commState() }},
		{"comm", func() { _ = el.comm(tid) }},
		{"cached", func() { _, _ = el.commState().cached(tid) }},
		{"setCachedComm", func() { el.setCachedComm(tid, "warm") }},
		{"fdState", func() { _ = el.fdState() }},
		{"pendingHandleState", func() { _ = el.pendingHandleState() }},
	}
	for _, check := range checks {
		if allocs := testing.AllocsPerRun(1000, check.fn); allocs != 0 {
			t.Errorf("%s on a warm cache allocates %.1f times per call, want 0", check.name, allocs)
		}
	}
}

// TestCommStateWarmCacheMutatorsDoNotAllocate extends the warm-cache pin to
// the other per-event entry points that go through commState and write to the
// cache: queueCommLookup on an already cached tid (the refresh-age branch,
// which must not queue a lookup) and setCachedCommFromKernel overwriting a
// cached tid. evictCachedComm is pinned on a warm map by evicting and
// re-caching the same tid, so every iteration exercises the delete path.
func TestCommStateWarmCacheMutatorsDoNotAllocate(t *testing.T) {
	// Above any pid_max, so the constructor's pid/ppid seeds never hit it.
	const tid = 1 << 30

	// A lookup that reached a worker would clear its pending flag once
	// resolveFn returned, hiding the enqueue from the check below. Blocking
	// resolveFn for tid until cleanup keeps every enqueued lookup of it
	// pending (queued or held by a worker), and the counter records each one
	// that started. Every other tid - the constructor's seeds - is answered
	// at once, so construction queues nothing. resolveFn is in place before
	// the loop exists, so no worker ever sees it change. Cleanups run
	// last-in first-out: the release registered below runs before the
	// shutdown newDeterministicLoop registered waits for the workers.
	var resolveCalls atomic.Int32
	release := make(chan struct{})
	el, resolver := newDeterministicLoop(t, func(ctx context.Context, got uint32) (string, error) {
		if got != tid {
			return seededComm, nil
		}
		resolveCalls.Add(1)
		<-release
		return "", ctx.Err()
	})
	t.Cleanup(func() { close(release) })

	el.setCachedComm(tid, "warm")
	// Warm up once outside the measurement: the first queueCommLookup starts
	// the lookup workers (goroutines, a one-time cost).
	el.queueCommLookup(tid)

	resolver.mu.RLock()
	ageBefore := resolver.commAges[tid]
	resolver.mu.RUnlock()

	if allocs := testing.AllocsPerRun(1000, func() { el.queueCommLookup(tid) }); allocs != 0 {
		t.Errorf("queueCommLookup(cached tid) on a warm cache allocates %.1f times per call, want 0", allocs)
	}
	// Checked right away, before any other call can touch the tid: the calls
	// above must have taken the refresh-age branch, advancing the LRU age
	// without queueing a lookup.
	resolver.mu.RLock()
	ageAfter := resolver.commAges[tid]
	_, pending := resolver.pending[tid]
	queued := len(resolver.lookupQueue)
	resolver.mu.RUnlock()
	if ageAfter <= ageBefore {
		t.Errorf("commAges[%d] = %d, want refreshed past %d", tid, ageAfter, ageBefore)
	}
	if pending || queued != 0 || resolveCalls.Load() != 0 {
		t.Errorf("queueCommLookup on a cached tid queued a lookup: pending=%v queued=%d resolveCalls=%d",
			pending, queued, resolveCalls.Load())
	}

	checks := []struct {
		name string
		fn   func()
	}{
		{"setCachedCommFromKernel", func() { el.setCachedCommFromKernel(tid, "kernel", math.MaxUint64) }},
		{"evictCachedComm+setCachedComm", func() {
			el.evictCachedComm(tid)
			el.setCachedComm(tid, "warm")
		}},
		{"evictCachedComm(uncached tid)", func() { el.evictCachedComm(tid + 1) }},
	}
	for _, check := range checks {
		if allocs := testing.AllocsPerRun(1000, check.fn); allocs != 0 {
			t.Errorf("%s on a warm cache allocates %.1f times per call, want 0", check.name, allocs)
		}
	}

	// The comm ends up as the last write left it.
	if got, ok := el.commState().cached(tid); !ok || got != "warm" {
		t.Errorf("cached(%d) = %q, %v; want %q, true", tid, got, ok, "warm")
	}
}

// TestCommStateZeroValueLoopIsWired covers a loop that never went through
// newEventLoop: the first commState call must create the resolver, complete
// its invariants and route its lookup failures to the loop's warning sink.
func TestCommStateZeroValueLoopIsWired(t *testing.T) {
	var el eventLoop
	var warnings []string
	el.SetWarningCallback(func(message string) { warnings = append(warnings, message) })

	resolver := el.commState()
	if resolver == nil || resolver != el.commResolver {
		t.Fatal("commState must create and keep the loop's resolver")
	}
	if resolver.comms == nil || resolver.pending == nil || resolver.lookupQueue == nil {
		t.Fatal("commState must complete the resolver's invariants")
	}
	if el.commState() != resolver {
		t.Fatal("commState must return the same resolver on every call")
	}

	resolver.notifyWarning("lookup failed")
	if len(warnings) != 1 || warnings[0] != "lookup failed" {
		t.Fatalf("resolver warnings = %q, want the loop's sink to receive exactly one", warnings)
	}
}

// TestCommStateWiresResolverAssignedToZeroValueLoop covers a loop that never
// went through newEventLoop but already carries a resolver: the resolver is
// non-nil yet was never wired, so the fast path must not return it as is. The
// first commState call must keep that resolver, complete its invariants and
// hand it the loop's warning sink; later calls take the fast path.
func TestCommStateWiresResolverAssignedToZeroValueLoop(t *testing.T) {
	var el eventLoop
	var warnings []string
	el.SetWarningCallback(func(message string) { warnings = append(warnings, message) })
	assigned := &commResolver{}
	el.commResolver = assigned

	if got := el.commState(); got != assigned {
		t.Fatalf("commState() = %p, want the assigned resolver %p", got, assigned)
	}
	if assigned.comms == nil || assigned.commAges == nil || assigned.pending == nil ||
		assigned.lookupQueue == nil || assigned.resolveFn == nil || assigned.lookupWorkers <= 0 {
		t.Fatal("commState must run ensureInitialized on an assigned, unwired resolver")
	}
	if assigned.warningFn == nil {
		t.Fatal("commState must wire the loop's warning sink into an assigned, unwired resolver")
	}
	assigned.notifyWarning("from assigned")
	if len(warnings) != 1 || warnings[0] != "from assigned" {
		t.Fatalf("warnings = %q, want the loop's sink to receive exactly one", warnings)
	}

	// The resolver is wired now: it must work as a cache and stay on the
	// allocation-free fast path.
	el.setCachedComm(7, "seven")
	if got, ok := el.commState().cached(7); !ok || got != "seven" {
		t.Fatalf("cached(7) = %q, %v; want %q, true", got, ok, "seven")
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = el.commState() }); allocs != 0 {
		t.Errorf("commState after wiring allocates %.1f times per call, want 0", allocs)
	}
	if el.commState() != assigned {
		t.Fatal("commState must keep returning the assigned resolver")
	}
}

// TestCommStateWiresSwappedResolver is the negative case for the fast path:
// a resolver installed after the loop was wired (a hand-built zero value
// here) must still be completed and wired on its first use rather than being
// mistaken for the already-wired one.
func TestCommStateWiresSwappedResolver(t *testing.T) {
	el, _ := newDeterministicLoop(t, seededResolveFn)
	var warnings []string
	el.SetWarningCallback(func(message string) { warnings = append(warnings, message) })
	wired := el.commState() // the loop's own resolver is now on the fast path

	swapped := &commResolver{}
	el.commResolver = swapped
	if got := el.commState(); got != swapped || got == wired {
		t.Fatal("commState must return the swapped-in resolver")
	}
	if swapped.comms == nil || swapped.pending == nil || swapped.resolveFn == nil {
		t.Fatal("a swapped-in resolver must have its invariants completed")
	}
	swapped.notifyWarning("from swapped")
	if len(warnings) != 1 || warnings[0] != "from swapped" {
		t.Fatalf("warnings = %q, want the swapped resolver wired to the loop's sink", warnings)
	}
}

// TestCommStateKeepsInjectedWarningSink pins that the one-time wiring still
// defers to a sink the injected resolver already carries.
func TestCommStateKeepsInjectedWarningSink(t *testing.T) {
	var injected []string
	resolver := newCommResolver(nil)
	resolver.resolveFn = seededResolveFn
	resolver.warningFn = func(message string) { injected = append(injected, message) }

	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(el.shutdownCommResolver)
	assertNoLookupQueued(t, resolver)
	if len(injected) != 0 {
		t.Fatalf("seeding reported %q, want no warnings from a resolver that answers every tid", injected)
	}
	el.SetWarningCallback(func(string) { t.Fatal("the loop's sink must not replace an injected one") })

	if el.commState() != resolver {
		t.Fatal("commState must return the injected resolver")
	}
	resolver.notifyWarning("injected")
	if len(injected) != 1 || injected[0] != "injected" {
		t.Fatalf("injected sink got %q, want exactly one warning", injected)
	}
}
