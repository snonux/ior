package internal

import (
	"testing"

	"ior/internal/file"
)

// The trackers own their invariants: the loop's injection seam
// (configuredFDTracker/configuredCommResolver) and the state accessors
// (fdState/commState/pendingHandleState) must be able to complete ANY
// tracker - including a hand-built one carrying entries without its
// metadata - without the loop spelling out the tracker's map fields. These
// tests pin exactly that, because the field-poking they replace is what
// previously made the fd-map representation live in three files (and let
// the (pid,fd) re-keying land half-done with the loop still allocating the
// old map type).

// TestFDTrackerEnsureInitCompletesHandBuiltState covers the tracker that
// carries entries but no metadata: ensureInit must seed the per-pid index
// from both maps so deletePid, which only consults the index, cannot
// silently skip eviction.
func TestFDTrackerEnsureInitCompletesHandBuiltState(t *testing.T) {
	fdt := &fdTracker{}
	// Hand-build entries the way an injected fixture would: files and procfs
	// cache contents, but no ages and no per-pid index.
	fdt.files = map[uint64]file.File{
		fdKey(42, 3): file.NewFd(3, "/tmp/one.txt", 0),
	}
	fdt.procFdCache = map[uint64]*file.FdFile{
		fdKey(42, 6): file.NewFdWithPid(6, 42),
	}

	fdt.ensureInit()

	if fdt.fileAges == nil || fdt.procFdAges == nil {
		t.Fatal("ensureInit must allocate the LRU age metadata")
	}
	if fdt.pidIndex == nil {
		t.Fatal("ensureInit must allocate the per-pid index")
	}
	keys, ok := fdt.pidIndex[42]
	if !ok || len(keys.files) != 1 || len(keys.cache) != 1 {
		t.Fatal("the per-pid index must be seeded from the pre-existing entries of both maps")
	}

	// The seeded index is what lets a process exit evict the hand-built
	// entries; deletePid only consults the index, so without it the entries
	// would be skipped silently.
	fdt.deletePid(42)
	if _, ok := fdt.get(3, 42); ok {
		t.Fatal("expected the hand-built fd entry to be evicted by deletePid")
	}
	if _, ok := fdt.cachedProcFdFile(6, 42); ok {
		t.Fatal("expected the hand-built cache entry to be evicted by deletePid")
	}
}

// TestPendingHandleTrackerZeroValueIsUsable pins the usable-zero-value
// contract: a tracker that never went through ensureInit must still be safe
// to read from, and its first set() must complete the initialization.
func TestPendingHandleTrackerZeroValueIsUsable(t *testing.T) {
	var tracker pendingHandleTracker

	if _, ok := tracker.peek(1); ok {
		t.Fatal("peeking a zero-value tracker must not report a hit")
	}
	tracker.delete(1) // deleting from nil maps must be a no-op, not a panic
	tracker.set(1, "/tmp/handle.txt")
	if pathname, ok := tracker.peek(1); !ok || pathname != "/tmp/handle.txt" {
		t.Fatalf("peek after set = (%q, %v), want the stored pathname", pathname, ok)
	}
	tracker.delete(1)
	if _, ok := tracker.peek(1); ok {
		t.Fatal("a deleted entry must not be peekable")
	}
}

// TestCommResolverZeroValueIsUsable pins that the resolver's own methods make
// a zero value work, so the loop never has to allocate its internals.
func TestCommResolverZeroValueIsUsable(t *testing.T) {
	var resolver commResolver

	resolver.ensureInitialized()
	if resolver.comms == nil || resolver.pending == nil {
		t.Fatal("ensureInitialized must allocate the cache and pending set")
	}
	if resolver.lookupQueue == nil || resolver.resolveFn == nil {
		t.Fatal("ensureInitialized must complete the lookup configuration")
	}

	// setDefaultWarningFn installs only when absent, so injected sinks win.
	calls := 0
	resolver.setDefaultWarningFn(func(string) { calls++ })
	resolver.setDefaultWarningFn(func(string) { t.Fatal("must not override an existing sink") })
	resolver.notifyWarning("one")
	if calls != 1 {
		t.Fatalf("warning sink called %d times, want exactly 1", calls)
	}
}
