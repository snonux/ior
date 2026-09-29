package internal

import (
	"math/rand/v2"
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

// applyRandomFdOp performs one randomly chosen mutation on a small (pid, fd)
// space, so collisions, re-registrations and every removal path - close,
// close_range (bounded and open-ended), exit, exec, cache deletes and LRU
// evictions under the tiny caps - are all exercised.
func applyRandomFdOp(rng *rand.Rand, fdt *fdTracker) {
	pid := uint32(1 + rng.IntN(4))
	fd := int32(rng.IntN(8))
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
		applyRandomFdOp(rng, fdt)
		assertFdIndexConsistent(t, fdt)
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
	live := make(map[*pidFdKeys]struct{}, len(fdt.pidIndex))
	for _, keys := range fdt.pidIndex {
		live[keys] = struct{}{}
	}
	for _, keys := range fdt.idlePidKeys {
		if len(keys.files) != 0 || len(keys.cache) != 0 {
			t.Fatalf("parked index entry is not empty: files %v cache %v", keys.files, keys.cache)
		}
		if _, ok := live[keys]; ok {
			t.Fatal("parked index entry is still in use by a pid")
		}
	}
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
