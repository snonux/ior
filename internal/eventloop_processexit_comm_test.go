package internal

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

// The comm cache is keyed by tid, and the kernel hands tid numbers out again
// as soon as the task that held one is reaped. These tests model exactly that:
// execCommTid is first owned by "victim", which exits, and the same number is
// then handed to "newproc".
const (
	deadComm    = "victim"
	recycleComm = "newproc"
)

// newRecyclingCommResolver builds a resolver whose procfs reads report
// whatever process currently owns execCommTid, so a lookup issued after the
// exit sees the new owner exactly as /proc would. Reads for any other tid (the
// tracer's own pid, seeded at construction) answer empty so the test never
// depends on the host.
func newRecyclingCommResolver(owner *atomic.Value) *commResolver {
	r := newCommResolver(nil)
	r.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		if tid != execCommTid {
			return "", nil
		}
		return owner.Load().(string), nil
	}
	return r
}

// feedTidSyscall pushes one access() enter/exit pair for execCommTid through
// the raw event path and returns the emitted row, so the assertions below are
// about the comm a row actually carries rather than about cache internals.
func feedTidSyscall(t *testing.T, el *eventLoop, at uint64) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterPathEvent(t, at, execCommPid, execCommTid,
		"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
	_, exitRaw := makeExitRetEvent(t, at+100, execCommPid, execCommTid,
		types.SYS_EXIT_ACCESS, -2)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// commOfNextSyscall feeds one syscall pair and reports the comm of the row it
// produced, failing when the pair was dropped.
func commOfNextSyscall(t *testing.T, el *eventLoop, at uint64) string {
	t.Helper()
	ep := feedTidSyscall(t, el, at)
	if ep == nil {
		t.Fatal("expected the syscall pair to be emitted")
	}
	defer ep.Recycle()
	return ep.Comm
}

// waitForCachedComm blocks until the resolver's cache reports want for
// execCommTid.
func waitForCachedComm(t *testing.T, el *eventLoop, want string) {
	t.Helper()
	waitForCondition(t, 2*time.Second, "timed out waiting for comm "+want, func() bool {
		got, ok := el.commState().cached(execCommTid)
		return ok && got == want
	})
}

// waitForNoPendingLookup blocks until the resolver has finished (and stored, or
// discarded) the lookup in flight for execCommTid.
func waitForNoPendingLookup(t *testing.T, r *commResolver) {
	t.Helper()
	waitForCondition(t, 2*time.Second, "timed out waiting for the in-flight lookup to land", func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		_, pending := r.pending[execCommTid]
		return !pending
	})
}

// TestRecycledTidDoesNotInheritTheDeadProcessComm is the regression test for
// the comm cache never being invalidated on process exit. Nothing but an
// execve, a kernel-sourced payload comm or LRU eviction ever overwrote an
// entry, so the next process handed the same tid number was labelled with the
// dead one's name - which is what a live capture showed, rows of a short-lived
// repro process carrying a neighbouring process's comm.
func TestRecycledTidDoesNotInheritTheDeadProcessComm(t *testing.T) {
	var owner atomic.Value
	owner.Store(deadComm)
	resolver := newRecyclingCommResolver(&owner)
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(resolver.shutdown)

	el.queueCommLookup(execCommTid)
	waitForCachedComm(t, el, deadComm)
	if got := commOfNextSyscall(t, el, defaulTime); got != deadComm {
		t.Fatalf("comm of the dying process's own row = %q, want %q", got, deadComm)
	}

	// The kernel reports the task gone; the tid number is free again.
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+200, execCommPid, execCommTid),
		make(chan *event.Pair, 1))
	if got, ok := el.commState().cached(execCommTid); ok {
		t.Fatalf("comm %q still cached for a tid the kernel reported as exited", got)
	}

	// A new process gets the recycled tid. Its syscalls must never be labelled
	// with the dead process's name.
	owner.Store(recycleComm)
	if got := commOfNextSyscall(t, el, defaulTime+400); got == deadComm {
		t.Fatalf("recycled tid inherited the dead process's comm %q", got)
	}
	waitForCachedComm(t, el, recycleComm)
	if got := commOfNextSyscall(t, el, defaulTime+600); got != recycleComm {
		t.Fatalf("comm after the tid was recycled = %q, want %q", got, recycleComm)
	}
}

// TestExitEvictionSurvivesAnInFlightLookup is the other half of the fix, and
// the reason the eviction cannot simply delete the map entry and be done.
// commResolver runs its procfs reads asynchronously: a worker that sampled the
// tid's state before the exit is still holding the dead process's name when the
// eviction runs. Landing it afterwards would reinstate exactly the entry the
// eviction removed - undetectably, because both writes are mutex-protected, so
// this is a logical race no detector can see.
func TestExitEvictionSurvivesAnInFlightLookup(t *testing.T) {
	var owner atomic.Value
	owner.Store(deadComm)
	resolver := newRecyclingCommResolver(&owner)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	// Released at the point the test needs it, but also on every other exit
	// path: a t.Fatal on the handshake below would otherwise leave a worker
	// parked in resolveFn and deadlock the registered resolver.shutdown,
	// replacing the assertion failure with a ten-minute timeout and a
	// goroutine dump.
	releaseWorker := sync.OnceFunc(func() { close(release) })
	defer releaseWorker()
	read := resolver.resolveFn
	resolver.resolveFn = func(ctx context.Context, tid uint32) (string, error) {
		if tid != execCommTid {
			return read(ctx, tid)
		}
		// The worker has already sampled the generation counters at this
		// point, which is precisely the window the exit has to survive.
		started <- struct{}{}
		<-release
		return read(ctx, tid)
	}

	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(resolver.shutdown)

	el.queueCommLookup(execCommTid)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the comm lookup to start")
	}

	el.processRawEvent(makeProcessExitEvent(t, defaulTime, execCommPid, execCommTid),
		make(chan *event.Pair, 1))
	releaseWorker()
	waitForNoPendingLookup(t, resolver)

	if got, ok := el.commState().cached(execCommTid); ok {
		t.Fatalf("in-flight lookup resurrected the evicted comm %q", got)
	}

	// The tid is handed to a new process, whose first syscall triggers the
	// fresh lookup. Nothing may report the dead process's name from here on -
	// and the retired lookup must not have poisoned the tid for good either,
	// so the new name has to arrive.
	owner.Store(recycleComm)
	if got := commOfNextSyscall(t, el, defaulTime+200); got == deadComm {
		t.Fatalf("row after the exit carries the resurrected comm %q", got)
	}
	waitForCachedComm(t, el, recycleComm)
	if got := commOfNextSyscall(t, el, defaulTime+400); got != recycleComm {
		t.Fatalf("comm after the recycled tid was resolved = %q, want %q", got, recycleComm)
	}
}

// TestProcessExitEvictsOnlyTheExitedTasksComm pins the granularity claim in
// handleProcessExitEvent: sched_process_exit fires per task and the comm cache
// is keyed per task, so a thread exit must drop that thread's name and nothing
// else. Evicting by tgid instead would blank every sibling thread of a
// still-living multithreaded process.
func TestProcessExitEvictsOnlyTheExitedTasksComm(t *testing.T) {
	const siblingTid = execCommTid + 1
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)

	el.setCachedComm(execCommTid, deadComm)
	el.setCachedComm(siblingTid, "sibling")

	// A thread exit (group_dead clear): the process lives on, yet the dead
	// thread's tid-keyed name must still go.
	el.processRawEvent(makeThreadExitEvent(t, defaulTime, execCommPid, execCommTid),
		make(chan *event.Pair, 1))

	if got, ok := el.commState().cached(execCommTid); ok {
		t.Fatalf("comm %q still cached for the exited task", got)
	}
	if got, ok := el.commState().cached(siblingTid); !ok || got != "sibling" {
		t.Fatalf("sibling thread comm = %q (present=%v), want \"sibling\"", got, ok)
	}
}

// TestLookupSampledAfterAnEvictionIsAccepted pins the positive direction of
// the eviction guard, which the other tests only cover indirectly.
//
// An exit record can land after a lookup was enqueued but before its worker
// sampled the generation counters. That worker then samples the *bumped*
// value, and its procfs read therefore happens after the exit - so the name it
// comes back with belongs to whoever holds the tid now, and discarding it
// would be wrong: the recycled tid would keep going back to procfs and never
// cache a name.
//
// The interleaving is between two points inside the resolver - the enqueue and
// the worker's sample - with no seam to drive it through the event loop, so
// the state machine is stepped directly. The pending flag is set by hand for
// the same reason: going through queueLookup would start real workers that
// would race these steps.
func TestLookupSampledAfterAnEvictionIsAccepted(t *testing.T) {
	resolver := newCommResolver(nil)
	t.Cleanup(resolver.shutdown)

	const tid = uint32(4242)
	resolver.setCachedFromKernel(tid, "dead-owner")
	resolver.mu.Lock()
	if resolver.pending == nil {
		resolver.pending = make(map[uint32]struct{})
	}
	resolver.pending[tid] = struct{}{}
	resolver.mu.Unlock()

	// The exit lands while that lookup is pending but before its worker
	// sampled, so the counter is bumped for it.
	resolver.evictTid(tid)
	if got, ok := resolver.cached(tid); ok {
		t.Fatalf("comm %q survived the eviction", got)
	}

	// The worker now samples - reading the bumped counter - and lands.
	state := resolver.sampleLookupState(tid)
	if state.evictGen == 0 {
		t.Fatal("the eviction did not bump the counter for a pending lookup; this test would prove nothing")
	}
	resolver.storeLookupResult(tid, "recycled-owner", state)

	got, ok := resolver.cached(tid)
	if !ok {
		t.Fatal("a lookup that sampled after the eviction was discarded; the recycled tid would never cache a name")
	}
	if got != "recycled-owner" {
		t.Fatalf("cached comm = %q, want the recycled owner's name", got)
	}
}
