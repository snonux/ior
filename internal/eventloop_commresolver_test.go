package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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
	defer resolver.shutdown()
	resolver.lookupWorkers = workers
	resolver.lookupQueue = make(chan uint32, lookups)
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		current := atomic.AddInt32(&running, 1)
		setMaxInt32(&maxRunning, current)
		started <- struct{}{}
		<-release
		atomic.AddInt32(&running, -1)
		wg.Done()
		return fmt.Sprintf("comm-%d", tid), nil
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
	defer resolver.shutdown()
	resolver.lookupWorkers = 1
	resolver.lookupQueue = make(chan uint32, 1)
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return fmt.Sprintf("comm-%d", tid), nil
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

func TestCommResolverShutdownStopsWorkersAndPreventsNewLookups(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	resolver := newCommResolver(nil)
	resolver.lookupWorkers = 1
	resolver.lookupQueue = make(chan uint32, 1)
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		started <- struct{}{}
		<-release
		return fmt.Sprintf("comm-%d", tid), nil
	}

	const activeTID uint32 = 201
	const postShutdownTID uint32 = 202

	resolver.queueLookup(activeTID)
	waitForStarts(t, started, 1, 2*time.Second)

	shutdownDone := make(chan struct{})
	go func() {
		resolver.shutdown()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned before in-flight lookup completed")
	case <-time.After(75 * time.Millisecond):
	}

	close(release)
	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolver shutdown")
	}

	resolver.queueLookup(postShutdownTID)
	if hasPending(resolver, postShutdownTID) {
		t.Fatalf("expected no pending entry after shutdown for tid %d", postShutdownTID)
	}
	if _, ok := resolver.cached(postShutdownTID); ok {
		t.Fatalf("did not expect tid %d to resolve after shutdown", postShutdownTID)
	}
	if pending := pendingCount(resolver); pending != 0 {
		t.Fatalf("expected no pending lookups after shutdown, got %d", pending)
	}
}

func TestCommResolverLookupWarnsOnUnexpectedResolveError(t *testing.T) {
	const tid uint32 = 301

	warnings := make(chan string, 1)
	resolver := newCommResolver(nil)
	defer resolver.shutdown()
	resolver.lookupWorkers = 1
	resolver.lookupQueue = make(chan uint32, 1)
	resolver.warningFn = func(message string) { warnings <- message }
	resolver.resolveFn = func(context.Context, uint32) (string, error) {
		return "", errors.New("boom")
	}

	resolver.queueLookup(tid)

	waitForCondition(t, 2*time.Second, "expected failed lookup to clear pending state", func() bool {
		return pendingCount(resolver) == 0
	})
	if _, ok := resolver.cached(tid); ok {
		t.Fatalf("did not expect tid %d to be cached after resolve failure", tid)
	}

	select {
	case message := <-warnings:
		if message == "" || !strings.Contains(message, "boom") {
			t.Fatalf("expected warning to mention boom, got %q", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolve warning")
	}
}

func TestResolveCommFromProcWithErrorIgnoresMissingProcess(t *testing.T) {
	comm, err := resolveCommFromProcWithError(^uint32(0))
	if err != nil {
		t.Fatalf("expected missing procfs entries to be handled without error, got %v", err)
	}
	if comm != "" {
		t.Fatalf("expected no comm for missing pid, got %q", comm)
	}
}

// TestResolveCommOfAGoneTaskSkipsTheExeFallback pins task xr2's early return:
// a comm read failing with ENOENT means the task is gone, so the exe readlink
// is not tried. The fake /proc/<tid> keeps an exe link next to the missing
// comm, so a fallback that ran would return the link's basename. A comm read
// failing for another reason (here EISDIR) still falls back to it.
func TestResolveCommOfAGoneTaskSkipsTheExeFallback(t *testing.T) {
	const tid = 4242
	for _, tc := range []struct {
		name     string
		makeComm func(t *testing.T, path string)
		want     string
	}{
		{"comm missing (ENOENT)", func(*testing.T, string) {}, ""},
		{"comm unreadable (EISDIR)", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "fallback-exe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			taskDir := procTidPathIn(root, tid)
			if err := os.Mkdir(taskDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/bin/fallback-exe", taskDir+"/exe"); err != nil {
				t.Fatal(err)
			}
			tc.makeComm(t, taskDir+"/comm")
			comm, _ := resolveCommFromProcRoot(root, tid)
			if comm != tc.want {
				t.Fatalf("comm = %q, want %q", comm, tc.want)
			}
		})
	}
}

// TestCommResolverLookupWorkerRespectsTimeout verifies that a resolveFn that
// blocks longer than resolveCommTimeout is interrupted and the pending entry
// is cleared so shutdown is not stalled.
func TestCommResolverLookupWorkerRespectsTimeout(t *testing.T) {
	const tid uint32 = 401

	// blockUntilCtxDone blocks until the context passed by the worker expires.
	blockUntilCtxDone := make(chan struct{})
	resolver := newCommResolver(nil)
	defer resolver.shutdown()
	resolver.lookupWorkers = 1
	resolver.lookupQueue = make(chan uint32, 1)
	resolver.resolveFn = func(ctx context.Context, _ uint32) (string, error) {
		close(blockUntilCtxDone)
		<-ctx.Done()
		return "", ctx.Err()
	}

	resolver.queueLookup(tid)

	// Wait until the resolver fn has started and confirmed it is blocking.
	select {
	case <-blockUntilCtxDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolver fn to start")
	}

	// The pending entry must be cleared once the context times out and the
	// worker loop continues to the next iteration.
	waitForCondition(t, resolveCommTimeout+2*time.Second,
		"expected pending entry to be cleared after context timeout",
		func() bool { return pendingCount(resolver) == 0 },
	)

	if _, ok := resolver.cached(tid); ok {
		t.Fatalf("did not expect tid %d to be cached after a timed-out resolve", tid)
	}
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

	timer := time.NewTimer(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()

	for {
		if fn() {
			return
		}
		select {
		case <-timer.C:
			t.Fatal(message)
		case <-ticker.C:
		}
	}
}

// TestReadWithDeadlineAbandonsHungRead pins the property the default
// resolver's timeout used to promise but not have: a procfs read stuck inside
// the kernel (D-state task, frozen cgroup - a read os.ReadFile cannot be
// interrupted out of) must not make the caller wait past the context deadline.
// readWithDeadline runs the read in a helper goroutine and abandons it, so the
// caller returns when ctx expires even though the read never will.
func TestReadWithDeadlineAbandonsHungRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := make(chan struct{})
	start := time.Now()
	comm, err := readWithDeadline(ctx, func() (string, error) {
		close(started)
		// A read that never returns: models the uninterruptible kernel read.
		select {}
	})
	elapsed := time.Since(start)

	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the context deadline error, got comm=%q err=%v", comm, err)
	}
	if comm != "" {
		t.Fatalf("expected an empty comm on timeout, got %q", comm)
	}
	if elapsed > time.Second {
		t.Fatalf("the abandoned read made the caller wait %v, far past its deadline", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("expected the helper goroutine to have started the read")
	}
}

// TestReadWithDeadlineReturnsFastResult pins the other half: a read that
// finishes before the deadline is returned as-is, with no error.
func TestReadWithDeadlineReturnsFastResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	comm, err := readWithDeadline(ctx, func() (string, error) {
		return "bash", nil
	})
	if err != nil || comm != "bash" {
		t.Fatalf("expected the fast read's result, got comm=%q err=%v", comm, err)
	}
}

// TestResolveCommWithinCtxBoundedByContext exercises the real default
// resolver with an already-expired context: it must return promptly instead of
// waiting for the underlying /proc read, which is exactly the guarantee the
// lookup workers and seedTrackedPidComm rely on to stay bounded.
func TestResolveCommWithinCtxBoundedByContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done() // make the deadline certain before entering

	start := time.Now()
	comm, err := resolveCommWithinCtx(ctx, uint32(os.Getpid()))
	if time.Since(start) > time.Second {
		t.Fatalf("cancelled-context resolve took %v, want a prompt return", time.Since(start))
	}
	// Either branch is fine: the read of our own /proc entry is
	// near-instant and may complete before the scheduler runs the select.
	// What must never happen is a long wait.
	if err == nil && comm == "" {
		t.Fatal("a completed read of a live tid must yield a non-empty comm")
	}
}

// TestCommResolverShutdownDropsQueuedLookups pins the prompt-teardown half of
// the fix: shutdown() is blocked on workersWG.Wait(), and the worker loop
// drains the remaining queue items without paying their procfs reads once the
// resolver is closed. Before the closed-check, a queue of N lookups on a
// system with hanging /proc entries cost up to N*resolveCommTimeout of
// teardown; without the abandonment fix a single stuck read hung teardown
// forever.
func TestCommResolverShutdownDropsQueuedLookups(t *testing.T) {
	const queued = 50

	var calls atomic.Int64
	inFlight := make(chan struct{})
	releaseAll := make(chan struct{})
	t.Cleanup(func() { close(releaseAll) })

	resolver := newCommResolver(nil)
	resolver.lookupWorkers = 1
	resolver.lookupQueue = make(chan uint32, queued)
	resolver.resolveFn = func(ctx context.Context, _ uint32) (string, error) {
		calls.Add(1)
		// Signal that the worker is inside a resolve, so the test can start
		// the shutdown while one read is in flight and pin exactly that branch.
		select {
		case inFlight <- struct{}{}:
		default:
		}
		// Honour the worker's timeout, but pay it in full: every processed
		// item costs resolveCommTimeout, so resolving the whole queue would
		// take queued*resolveCommTimeout.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-releaseAll:
			return "", nil
		}
	}

	resolver.startLookupWorkers()
	for i := 0; i < queued; i++ {
		resolver.queueLookup(uint32(1000 + i))
	}

	// Wait until the worker is genuinely inside the first resolve, so the
	// shutdown below exercises the in-flight branch: one resolve completes
	// (its context timeout), everything queued behind it is drained by the
	// closed-skip.
	select {
	case <-inFlight:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the worker to enter its first resolve")
	}

	start := time.Now()
	resolver.shutdown()
	elapsed := time.Since(start)

	// The worker is inside one resolve when shutdown lands (waited for
	// above): it pays that one resolveCommTimeout, then everything queued
	// behind it must be drained without further reads. Five timeouts of
	// headroom allows for scheduling noise while still failing the
	// queued*1s worst case (~50s) decisively.
	if elapsed > 5*resolveCommTimeout {
		t.Fatalf("shutdown took %v for a queue of %d lookups, want a prompt drain", elapsed, queued)
	}
	if got := calls.Load(); got > 2 {
		t.Fatalf("resolved %d lookups during shutdown, want at most the in-flight one", got)
	}
	if got := pendingCount(resolver); got != 0 {
		t.Fatalf("pending map still holds %d entries after shutdown", got)
	}
}
