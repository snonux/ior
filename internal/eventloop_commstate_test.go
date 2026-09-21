package internal

import (
	"testing"
)

// commState runs several times per traced event (comm, cachedComm,
// queueCommLookup, setCachedComm*), so its steady state must not allocate.
// It used to re-evaluate the method value e.notifyWarning on every call,
// which heap-allocates a closure and accounted for ~46% of all pipeline
// allocations. These tests pin the one-time wiring and its allocation cost.

// TestCommStateWarmCacheDoesNotAllocate pins the fix: resolving a cached comm
// through the loop, and fetching the other per-event trackers, costs zero
// heap allocations.
func TestCommStateWarmCacheDoesNotAllocate(t *testing.T) {
	const tid = 4242
	el := mustNewEventLoop(t, eventLoopConfig{})
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
		{"cachedComm", func() { _, _ = el.cachedComm(tid) }},
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

// TestCommStateWiresSwappedResolver is the negative case for the fast path:
// a resolver installed after the loop was wired (a hand-built zero value
// here) must still be completed and wired on its first use rather than being
// mistaken for the already-wired one.
func TestCommStateWiresSwappedResolver(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
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
	resolver.warningFn = func(message string) { injected = append(injected, message) }

	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	el.SetWarningCallback(func(string) { t.Fatal("the loop's sink must not replace an injected one") })

	if el.commState() != resolver {
		t.Fatal("commState must return the injected resolver")
	}
	resolver.notifyWarning("injected")
	if len(injected) != 1 || injected[0] != "injected" {
		t.Fatalf("injected sink got %q, want exactly one warning", injected)
	}
}
