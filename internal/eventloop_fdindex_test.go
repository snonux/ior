package internal

import (
	"math/rand/v2"
	"reflect"
	"syscall"
	"testing"

	"ior/internal/file"
)

// Benchmark shape for the per-pid lookups the exec and exit control records
// run on the single event-loop goroutine: a fd table and a procfs cache filled
// to their default caps (32768 / 8192 entries) over many processes, and one
// process with a handful of descriptors being exec'd or exiting.
const (
	benchFdsPerPid   = 8
	benchTargetPid   = 1
	benchFirstPid    = 2
	benchCacheFdBase = 1000
)

// newFullFdTracker fills the fd table and procfs cache to their default caps
// with known-clear (exec-surviving) entries, spread over benchFdsPerPid
// descriptors per process, plus benchFdsPerPid entries in each map for
// benchTargetPid.
func newFullFdTracker(b *testing.B) *fdTracker {
	b.Helper()
	fdt := newFDTracker(nil)
	fill := func(pid uint32, fd int32) {
		fdt.set(fd, pid, file.NewFd(fd, "/bench", syscall.O_RDONLY))
		fdt.setProcFdCache(fd+benchCacheFdBase, pid, file.NewFd(fd+benchCacheFdBase, "/bench-cache", syscall.O_RDONLY))
	}
	for fd := int32(0); fd < benchFdsPerPid; fd++ {
		fill(benchTargetPid, fd)
	}
	for i := 0; len(fdt.files) < defaultMaxFdTableEntries; i++ {
		pid := uint32(benchFirstPid + i/benchFdsPerPid)
		fd := int32(i % benchFdsPerPid)
		fdt.set(fd, pid, file.NewFd(fd, "/bench", syscall.O_RDONLY))
		if len(fdt.procFdCache) < defaultMaxProcFdCacheSize {
			fdt.setProcFdCache(fd+benchCacheFdBase, pid, file.NewFd(fd+benchCacheFdBase, "/bench-cache", syscall.O_RDONLY))
		}
	}
	return fdt
}

// BenchmarkDropOnExecFullTable measures one exec record for a process whose
// descriptors all survive the exec, so every iteration sees the same state.
func BenchmarkDropOnExecFullTable(b *testing.B) {
	fdt := newFullFdTracker(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fdt.dropOnExec(benchTargetPid)
	}
}

// BenchmarkDeletePidFullTable measures one process exit against full maps.
// The evicted entries are re-registered with the timer stopped so every
// iteration evicts the same benchFdsPerPid entries from each map.
func BenchmarkDeletePidFullTable(b *testing.B) {
	fdt := newFullFdTracker(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fdt.deletePid(benchTargetPid)
		b.StopTimer()
		for fd := int32(0); fd < benchFdsPerPid; fd++ {
			fdt.set(fd, benchTargetPid, file.NewFd(fd, "/bench", syscall.O_RDONLY))
			fdt.setProcFdCache(fd+benchCacheFdBase, benchTargetPid,
				file.NewFd(fd+benchCacheFdBase, "/bench-cache", syscall.O_RDONLY))
		}
		b.StartTimer()
	}
}

// BenchmarkCloseRangeFullTable measures close_range(3, ~0U) of one process
// against full maps, re-registering the closed entries off the clock.
func BenchmarkCloseRangeFullTable(b *testing.B) {
	fdt := newFullFdTracker(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fdt.closeRange(3, -1, benchTargetPid)
		fdt.deleteProcFdCacheRange(3, -1, benchTargetPid)
		b.StopTimer()
		for fd := int32(3); fd < benchFdsPerPid; fd++ {
			fdt.set(fd, benchTargetPid, file.NewFd(fd, "/bench", syscall.O_RDONLY))
		}
		b.StartTimer()
	}
}

// assertFdIndexConsistent checks the per-pid index against the maps it
// indexes: every key of files and procFdCache is in its pid's set, every
// indexed key exists in its map, and no pid with empty sets lingers.
func assertFdIndexConsistent(t *testing.T, fdt *fdTracker) {
	t.Helper()
	want := make(map[uint32]*pidFdKeys)
	entry := func(key uint64) *pidFdKeys {
		pid, _ := fdKeyParts(key)
		if want[pid] == nil {
			want[pid] = &pidFdKeys{files: map[uint64]struct{}{}, cache: map[uint64]struct{}{}}
		}
		return want[pid]
	}
	for key := range fdt.files {
		entry(key).files[key] = struct{}{}
	}
	for key := range fdt.procFdCache {
		entry(key).cache[key] = struct{}{}
	}
	if len(fdt.pidIndex) != len(want) {
		t.Fatalf("index has %d pids, maps own entries for %d", len(fdt.pidIndex), len(want))
	}
	for pid, wantKeys := range want {
		got, ok := fdt.pidIndex[pid]
		if !ok {
			t.Fatalf("pid %d owns entries but is missing from the index", pid)
		}
		if !sameKeySet(got.files, wantKeys.files) || !sameKeySet(got.cache, wantKeys.cache) {
			t.Fatalf("pid %d index = files %v cache %v, want files %v cache %v",
				pid, got.files, got.cache, wantKeys.files, wantKeys.cache)
		}
	}
	assertIdlePidKeysReusable(t, fdt)
	if len(fdt.fileAges) != len(fdt.files) || len(fdt.procFdAges) != len(fdt.procFdCache) {
		t.Fatalf("ages out of step: files %d/%d cache %d/%d",
			len(fdt.files), len(fdt.fileAges), len(fdt.procFdCache), len(fdt.procFdAges))
	}
}

func sameKeySet(a, b map[uint64]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

// randomFdFile returns an entry with one of the three close-on-exec states
// (known set, known clear, unknown), so dropOnExec takes every branch.
func randomFdFile(rng *rand.Rand, fd int32) *file.FdFile {
	switch rng.IntN(3) {
	case 0:
		return file.NewFd(fd, "/r", syscall.O_RDONLY|syscall.O_CLOEXEC)
	case 1:
		return file.NewFd(fd, "/r", syscall.O_RDONLY)
	default:
		return file.NewFd(fd, "/r", -1)
	}
}

// applyRandomFdOp performs one randomly chosen mutation on the (pid, fd)
// space [1, pids] x [0, fds), so collisions, re-registrations and every
// removal path - close, close_range (bounded and open-ended), exit, exec,
// cache deletes and LRU evictions under the caps - are all exercised.
func applyRandomFdOp(rng *rand.Rand, fdt *fdTracker, pids, fds int) {
	pid := uint32(1 + rng.IntN(pids))
	fd := int32(rng.IntN(fds))
	switch rng.IntN(10) {
	case 0, 1:
		fdt.set(fd, pid, randomFdFile(rng, fd))
	case 2:
		fdt.setProcFdCache(fd, pid, randomFdFile(rng, fd))
	case 3:
		fdt.delete(fd, pid)
	case 4:
		fdt.deleteProcFdCache(fd, pid)
	case 5:
		last := fd + int32(rng.IntN(4))
		if rng.IntN(2) == 0 {
			last = -1
		}
		fdt.closeRange(fd, last, pid)
		fdt.deleteProcFdCacheRange(fd, last, pid)
	case 6:
		fdt.addFlagsRange(fd, fd+2, pid, syscall.O_CLOEXEC)
	case 7:
		fdt.deletePid(pid)
	default:
		fdt.dropOnExec(pid)
	}
}

// TestFdIndexStaysConsistentUnderRandomOps drives a seeded random sequence of
// every fdTracker mutation and checks after each step that the per-pid index
// is exactly the one derived from the maps. Tiny caps make LRU eviction, the
// path that most easily forgets a side structure, fire constantly.
func TestFdIndexStaysConsistentUnderRandomOps(t *testing.T) {
	rng := rand.New(rand.NewPCG(8, 2))
	fdt := newFDTracker(nil)
	fdt.maxFiles = 10
	fdt.maxCacheSize = 6
	for step := 0; step < 20000; step++ {
		// More pids than maxIdlePidKeys, so the idle-list cap is exercised too.
		applyRandomFdOp(rng, fdt, maxIdlePidKeys+8, 8)
		assertFdIndexConsistent(t, fdt)
	}
}

// TestFdIndexStaysConsistentWithSetRebuilds is the second phase of the
// random-ops test: a few pids, descriptor numbers and caps well above
// maxRecycledSetSize, and bursts of registrations, so sets grow past the
// threshold and the shrinkKeySet rebuilds interleave with LRU eviction,
// close_range, deletePid and dropOnExec. It also counts the rebuilds of live
// fd-table and procfs-cache sets (a live entry whose peak drops), so a
// broken rebuild path cannot pass by never running.
func TestFdIndexStaysConsistentWithSetRebuilds(t *testing.T) {
	const pids, fds = 3, 8 * maxRecycledSetSize
	rng := rand.New(rand.NewPCG(8, 5))
	fdt := newFDTracker(nil)
	fdt.maxFiles = 2 * fds
	fdt.maxCacheSize = fds
	var fileRebuilds, cacheRebuilds int
	for step := 0; step < 20000; step++ {
		before := snapshotPeaks(fdt)
		if rng.IntN(25) == 0 {
			fillBurst(rng, fdt, pids, fds)
		} else {
			applyRandomFdOp(rng, fdt, pids, fds)
		}
		assertFdIndexConsistent(t, fdt)
		for pid, keys := range fdt.pidIndex {
			prev, ok := before[pid]
			if !ok || prev.keys != keys {
				continue
			}
			if keys.peakFiles < prev.files {
				fileRebuilds++
			}
			if keys.peakCache < prev.cache {
				cacheRebuilds++
			}
		}
	}
	if fileRebuilds == 0 || cacheRebuilds == 0 {
		t.Fatalf("live set rebuilds: files %d, cache %d; want both > 0", fileRebuilds, cacheRebuilds)
	}
}

type peakSnapshot struct {
	keys         *pidFdKeys
	files, cache int
}

func snapshotPeaks(fdt *fdTracker) map[uint32]peakSnapshot {
	snap := make(map[uint32]peakSnapshot, len(fdt.pidIndex))
	for pid, keys := range fdt.pidIndex {
		snap[pid] = peakSnapshot{keys: keys, files: keys.peakFiles, cache: keys.peakCache}
	}
	return snap
}

// fillBurst registers many descriptors of one pid in one of the two maps,
// pushing its set past maxRecycledSetSize.
func fillBurst(rng *rand.Rand, fdt *fdTracker, pids, fds int) {
	pid := uint32(1 + rng.IntN(pids))
	cache := rng.IntN(2) == 0
	for range 2 * maxRecycledSetSize {
		fd := int32(rng.IntN(fds))
		if cache {
			fdt.setProcFdCache(fd, pid, randomFdFile(rng, fd))
		} else {
			fdt.set(fd, pid, randomFdFile(rng, fd))
		}
	}
}

// TestPerPidOpsOnZeroValueTracker pins that the index-backed operations are
// safe on a tracker that never went through ensureInit, and that its first
// insertions build the index lazily.
func TestPerPidOpsOnZeroValueTracker(t *testing.T) {
	fdt := &fdTracker{}
	fdt.closeRange(0, -1, crossPidA)
	fdt.deleteProcFdCacheRange(0, -1, crossPidA)
	fdt.addFlagsRange(0, -1, crossPidA, syscall.O_CLOEXEC)
	fdt.dropOnExec(crossPidA)
	fdt.deletePid(crossPidA)
	fdt.delete(3, crossPidA)
	fdt.deleteProcFdCache(3, crossPidA)

	fdt.set(3, crossPidA, file.NewFd(3, "/z", syscall.O_RDONLY))
	fdt.setProcFdCache(4, crossPidA, file.NewFd(4, "/z", syscall.O_RDONLY))
	assertFdIndexConsistent(t, fdt)
	fdt.closeRange(0, -1, crossPidA)
	fdt.deleteProcFdCacheRange(0, -1, crossPidA)
	assertFdIndexConsistent(t, fdt)
	if len(fdt.pidIndex) != 0 {
		t.Fatalf("pid still indexed after all its entries were closed: %v", fdt.pidIndex)
	}
}

// assertIdlePidKeysReusable checks the recycling list: bounded, every parked
// entry empty, and none of them still reachable from the index (a parked
// entry handed to a second pid would merge two processes' key sets).
func assertIdlePidKeysReusable(t *testing.T, fdt *fdTracker) {
	t.Helper()
	if len(fdt.idlePidKeys) > maxIdlePidKeys {
		t.Fatalf("idle list holds %d entries, cap is %d", len(fdt.idlePidKeys), maxIdlePidKeys)
	}
	seen := make(map[*pidFdKeys]struct{}, len(fdt.pidIndex)+len(fdt.idlePidKeys))
	for _, keys := range fdt.pidIndex {
		if _, dup := seen[keys]; dup {
			t.Fatal("two pids share one index entry")
		}
		seen[keys] = struct{}{}
	}
	for _, keys := range fdt.idlePidKeys {
		if len(keys.files) != 0 || len(keys.cache) != 0 {
			t.Fatalf("parked index entry is not empty: files %v cache %v", keys.files, keys.cache)
		}
		if keys.peakFiles > maxRecycledSetSize || keys.peakCache > maxRecycledSetSize {
			t.Fatalf("parked entry kept an oversized set (peaks %d/%d)", keys.peakFiles, keys.peakCache)
		}
		if _, dup := seen[keys]; dup {
			t.Fatal("parked index entry is still in use by a pid or parked twice")
		}
		seen[keys] = struct{}{}
	}
}

// TestIdlePidKeysAreCapped parks more emptied entries than the idle list may
// hold and checks the cap: the extra entries are left to the collector.
func TestIdlePidKeysAreCapped(t *testing.T) {
	fdt := newFDTracker(nil)
	f := file.NewFd(3, "/cap", syscall.O_RDONLY)
	const pids = maxIdlePidKeys + 8
	for pid := uint32(1); pid <= pids; pid++ {
		fdt.set(3, pid, f)
	}
	for pid := uint32(1); pid <= pids; pid++ {
		fdt.deletePid(pid)
	}
	if got := len(fdt.idlePidKeys); got != maxIdlePidKeys {
		t.Fatalf("idle list holds %d entries after %d exits, want the cap %d", got, pids, maxIdlePidKeys)
	}
	assertFdIndexConsistent(t, fdt)
}

// TestIdlePidKeysDropOversizedSets is the regression test for recycling a
// once-busy process's bucket array: Go maps never shrink, so after a pid with
// many descriptors exits, its parked entry must not hand that set to the next
// short-lived pid, whose exec/exit would otherwise scan every bucket. The
// removals that drain the set rebuild it right-sized on the way down
// (shrinkKeySet), so what gets parked is either nothing or a fresh small map
// - never the original. Small sets must still be recycled as is (that is what
// keeps churn allocation-free).
func TestIdlePidKeysDropOversizedSets(t *testing.T) {
	const bigPid, smallPid, nextPid = 1, 2, 3
	fdt := newFDTracker(nil)
	f := file.NewFd(0, "/big", syscall.O_RDONLY)
	for fd := int32(0); fd < 8*maxRecycledSetSize; fd++ {
		fdt.set(fd, bigPid, f)
	}
	fdt.setProcFdCache(0, bigPid, f)
	bigSet := mapIdentity(fdt.pidIndex[bigPid].files)
	fdt.deletePid(bigPid)

	if n := len(fdt.idlePidKeys); n != 1 {
		t.Fatalf("idle list holds %d entries, want 1", n)
	}
	parked := fdt.idlePidKeys[0]
	if parked.files != nil && mapIdentity(parked.files) == bigSet {
		t.Fatal("parked entry kept the oversized files map")
	}
	if parked.peakFiles > maxRecycledSetSize {
		t.Fatalf("parked files set has peak %d, want <= %d", parked.peakFiles, maxRecycledSetSize)
	}
	if parked.cache == nil {
		t.Fatal("parked entry dropped a small cache set that should be recycled")
	}

	fdt.set(3, nextPid, f)
	if reused := fdt.pidIndex[nextPid]; reused != parked {
		t.Fatal("next pid did not reuse the parked entry")
	}

	// A set that stayed small is recycled as is, map included.
	fdt.set(3, smallPid, f)
	smallSet := mapIdentity(fdt.pidIndex[smallPid].files)
	fdt.deletePid(smallPid)
	if got := fdt.idlePidKeys[len(fdt.idlePidKeys)-1].files; got == nil || mapIdentity(got) != smallSet {
		t.Fatal("a small emptied set must be recycled, not dropped or rebuilt")
	}
	assertFdIndexConsistent(t, fdt)
}

// mapIdentity returns the runtime identity of a map, so tests can tell a
// rebuilt set from the original.
func mapIdentity(m map[uint64]struct{}) uintptr {
	return reflect.ValueOf(m).Pointer()
}

// BenchmarkFdSetDeleteChurn measures the most common fd-table pattern: a
// process opening and closing its only tracked descriptor. Its pid enters
// and leaves the index every iteration, so this is the path idlePidKeys
// keeps allocation-free.
func BenchmarkFdSetDeleteChurn(b *testing.B) {
	fdt := newFDTracker(nil)
	f := file.NewFd(3, "/churn", syscall.O_RDONLY)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fdt.set(3, benchTargetPid, f)
		fdt.delete(3, benchTargetPid)
	}
}

// BenchmarkFdNewPidLifecycle measures a stream of short-lived processes: each
// iteration's pid is new to the tracker, registers a descriptor and a procfs
// cache entry, and exits. The emptied entry of one process is recycled for
// the next.
func BenchmarkFdNewPidLifecycle(b *testing.B) {
	fdt := newFDTracker(nil)
	f := file.NewFd(3, "/lifecycle", syscall.O_RDONLY)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32(benchFirstPid + i)
		fdt.set(3, pid, f)
		fdt.setProcFdCache(4, pid, f)
		fdt.deletePid(pid)
	}
}

// BenchmarkNewPidAfterBigPidExit measures short-lived processes after one
// process holding 30000 descriptors exited. Its emptied entry is parked
// first and reused by the next pid; with the oversized set recycled, every
// exec/exit here ranged over ~30000 buckets.
func BenchmarkNewPidAfterBigPidExit(b *testing.B) {
	fdt := newFDTracker(nil)
	f := file.NewFd(3, "/big", syscall.O_RDONLY)
	for fd := int32(0); fd < 30000; fd++ {
		fdt.set(fd, benchTargetPid, f)
	}
	fdt.deletePid(benchTargetPid)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32(benchFirstPid + i)
		fdt.set(3, pid, f)
		fdt.dropOnExec(pid)
		fdt.deletePid(pid)
	}
}

// TestIdlePidKeysRecycleBoundary pins the exact threshold on both paths
// that apply it. parkPidEntry keeps a set whose peak is maxRecycledSetSize
// and drops one whose peak is one more; shrinkKeySet leaves a set at the
// threshold untouched however empty it gets, and rebuilds (or, when empty,
// drops) one just above it once fewer than peak/8 keys remain.
func TestIdlePidKeysRecycleBoundary(t *testing.T) {
	for _, tc := range []struct {
		peak     int
		wantKept bool
	}{
		{maxRecycledSetSize, true},
		{maxRecycledSetSize + 1, false},
	} {
		fdt := newFDTracker(nil)
		set := map[uint64]struct{}{}
		fdt.parkPidEntry(&pidFdKeys{files: set, peakFiles: tc.peak})
		if kept := fdt.idlePidKeys[0].files != nil; kept != tc.wantKept {
			t.Errorf("parkPidEntry peak %d: files set kept = %v, want %v", tc.peak, kept, tc.wantKept)
		}

		got, gotPeak := shrinkKeySet(set, tc.peak)
		if kept := got != nil && gotPeak == tc.peak; kept != tc.wantKept {
			t.Errorf("shrinkKeySet peak %d on an empty set: kept = %v, want %v", tc.peak, kept, tc.wantKept)
		}
	}

	// Just above the threshold, peak/8 is the rebuild point: at peak/8 keys
	// the set stays, one fewer and it is rebuilt right-sized.
	const peak = maxRecycledSetSize + 1
	set := make(map[uint64]struct{})
	for fd := int32(0); fd < peak/8; fd++ {
		set[fdKey(crossPidA, fd)] = struct{}{}
	}
	if got, gotPeak := shrinkKeySet(set, peak); mapIdentity(got) != mapIdentity(set) || gotPeak != peak {
		t.Fatalf("set with peak/8 keys was rebuilt (peak %d)", gotPeak)
	}
	delete(set, fdKey(crossPidA, 0))
	got, gotPeak := shrinkKeySet(set, peak)
	if mapIdentity(got) == mapIdentity(set) || gotPeak != len(set) || len(got) != len(set) {
		t.Fatalf("set below peak/8 not rebuilt right-sized: len %d peak %d", len(got), gotPeak)
	}
	for key := range set {
		if _, ok := got[key]; !ok {
			t.Fatalf("rebuild lost key %#x", key)
		}
	}
}

// TestLiveOversizedSetIsShrunk covers a process that stays alive after
// holding many descriptors: once fewer than peak/8 remain, its set is rebuilt
// right-sized so its per-pid operations stop scanning the old bucket array.
// Every remaining key must survive the rebuild, including when it happens
// in the middle of a closeRange or dropOnExec loop.
func TestLiveOversizedSetIsShrunk(t *testing.T) {
	const peak = 8 * maxRecycledSetSize
	fdt := newFDTracker(nil)
	for fd := int32(0); fd < peak; fd++ {
		flags := int32(syscall.O_RDONLY)
		if fd%2 == 1 {
			flags |= syscall.O_CLOEXEC
		}
		fdt.set(fd, crossPidA, file.NewFd(fd, "/many", flags))
	}
	// close_range down to four descriptors: 0-3 stay, the rebuild fires
	// mid-loop once fewer than peak/8 keys remain.
	bigSet := mapIdentity(fdt.pidIndex[crossPidA].files)
	fdt.closeRange(4, -1, crossPidA)
	keys := fdt.pidIndex[crossPidA]
	if keys == nil || len(keys.files) != 4 {
		t.Fatalf("index after close_range = %+v, want 4 keys", keys)
	}
	// The rebuild fires once, as soon as fewer than peak/8 keys remain; the
	// right-sized set it makes is below the threshold and is kept from then on.
	if mapIdentity(keys.files) == bigSet || keys.peakFiles > maxRecycledSetSize {
		t.Fatalf("set not rebuilt after shrinking to 4 keys (peak %d)", keys.peakFiles)
	}
	assertFdIndexConsistent(t, fdt)

	// Grow again, then let dropOnExec (which ranges over the set while it
	// may be swapped) remove the O_CLOEXEC half and more.
	for fd := int32(4); fd < peak; fd++ {
		fdt.set(fd, crossPidA, file.NewFd(fd, "/many", syscall.O_RDONLY|syscall.O_CLOEXEC))
	}
	fdt.dropOnExec(crossPidA)
	for fd := int32(0); fd < 4; fd++ {
		_, tracked := fdt.files[fdKey(crossPidA, fd)]
		if want := fd%2 == 0; tracked != want {
			t.Errorf("fd %d tracked after exec = %v, want %v", fd, tracked, want)
		}
	}
	if got := fdt.pidIndex[crossPidA]; got == nil || len(got.files) != 2 || got.peakFiles > maxRecycledSetSize {
		t.Fatalf("index after exec = %+v, want 2 keys in a right-sized set", got)
	}
	assertFdIndexConsistent(t, fdt)
}

// BenchmarkCloseRangeAfterShrink measures close_range on a live process that
// once held 30000 descriptors and now holds two: with the set rebuilt this
// costs O(2), not a scan of the old bucket array.
func BenchmarkCloseRangeAfterShrink(b *testing.B) {
	fdt := newFDTracker(nil)
	f := file.NewFd(0, "/many", syscall.O_RDONLY)
	for fd := int32(0); fd < 30000; fd++ {
		fdt.set(fd, benchTargetPid, f)
	}
	fdt.closeRange(2, -1, benchTargetPid)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fdt.closeRange(100, -1, benchTargetPid)
	}
}

// TestLiveOversizedCacheSetIsShrunk is the procfs-cache counterpart of
// TestLiveOversizedSetIsShrunk: the cache set of a live pid is rebuilt
// right-sized once drained, whether by deleteProcFdCacheRange (close_range)
// or by dropOnExec ranging over it.
func TestLiveOversizedCacheSetIsShrunk(t *testing.T) {
	const peak = 8 * maxRecycledSetSize
	fdt := newFDTracker(nil)
	fdt.maxCacheSize = 2 * peak
	fill := func(from int32) {
		for fd := from; fd < peak; fd++ {
			flags := int32(syscall.O_RDONLY)
			if fd%2 == 1 {
				flags |= syscall.O_CLOEXEC
			}
			fdt.setProcFdCache(fd, crossPidA, file.NewFd(fd, "/cached", flags))
		}
	}
	fill(0)
	bigSet := mapIdentity(fdt.pidIndex[crossPidA].cache)
	fdt.deleteProcFdCacheRange(4, -1, crossPidA)
	keys := fdt.pidIndex[crossPidA]
	if keys == nil || len(keys.cache) != 4 {
		t.Fatalf("index after cache range delete = %+v, want 4 cache keys", keys)
	}
	if mapIdentity(keys.cache) == bigSet || keys.peakCache > maxRecycledSetSize {
		t.Fatalf("cache set not rebuilt after shrinking to 4 keys (peak %d)", keys.peakCache)
	}
	assertFdIndexConsistent(t, fdt)

	// Grow again past the threshold, then let dropOnExec drain the
	// O_CLOEXEC half and trigger the rebuild while it ranges over the set.
	fill(4)
	bigSet = mapIdentity(fdt.pidIndex[crossPidA].cache)
	for fd := int32(4); fd < peak-2; fd++ {
		fdt.procFdCache[fdKey(crossPidA, fd)].MergeFlags(syscall.O_CLOEXEC, syscall.O_CLOEXEC)
	}
	fdt.dropOnExec(crossPidA)
	keys = fdt.pidIndex[crossPidA]
	// Survivors: fds 0 and 2 (known clear from the first fill) and peak-2
	// (even, never marked); peak-1 is odd and was opened O_CLOEXEC.
	if keys == nil || len(keys.cache) != 3 {
		t.Fatalf("index after exec = %+v, want 3 cache keys", keys)
	}
	if mapIdentity(keys.cache) == bigSet || keys.peakCache > maxRecycledSetSize {
		t.Fatalf("cache set not rebuilt by dropOnExec (peak %d)", keys.peakCache)
	}
	assertFdIndexConsistent(t, fdt)
}
