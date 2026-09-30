package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
)

// TestRepeatedGroupDeadRecordsCountOneDeath covers kernels whose tracepoint has
// no group_dead field: several threads of one exit_group can each read
// signal->live == 0 and each emit a group_dead=1 record. They are one process
// death and must move the counter once.
func TestRepeatedGroupDeadRecordsCountOneDeath(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(crossFd, crossPidA, file.NewFd(crossFd, "/tmp/dup-exit.txt", syscall.O_RDONLY))
	out := make(chan *event.Pair, 1)

	// Three threads of one process, microseconds apart, one arriving
	// slightly out of order as records from different CPUs can.
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+2_000, crossPidA, crossTidA), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+1_000, crossPidA, crossTidA+1), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+3_000, crossPidA, crossTidA+2), out)

	if el.numGroupDeadExits != 1 {
		t.Fatalf("numGroupDeadExits = %d for one process death reported by three threads, want 1", el.numGroupDeadExits)
	}
	if _, ok := el.fdState().get(crossFd, crossPidA); ok {
		t.Fatalf("pid %d fd %d still tracked after the process exited", crossPidA, crossFd)
	}
}

// TestGroupDeadOfDifferentPidsAreCountedSeparately is the negative test: the
// dedup is per pid, so simultaneous deaths of distinct processes all count.
func TestGroupDeadOfDifferentPidsAreCountedSeparately(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)

	el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+1, crossPidB, crossTidB), out)

	if el.numGroupDeadExits != 2 {
		t.Fatalf("numGroupDeadExits = %d for two distinct processes, want 2", el.numGroupDeadExits)
	}
}

// TestRecycledPidDeathIsCountedAgain is the other negative test: once the dedup
// window has passed, the same pid dying again is a new process and counts.
func TestRecycledPidDeathIsCountedAgain(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)

	el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+2*groupDeadDedupWindowNs, crossPidA, crossTidA), out)

	if el.numGroupDeadExits != 2 {
		t.Fatalf("numGroupDeadExits = %d for a recycled pid dying twice, want 2", el.numGroupDeadExits)
	}
}

// TestGroupDeadDedupMapStaysBounded checks that the per-pid memory is expired:
// a process-churning trace must not grow it without limit.
func TestGroupDeadDedupMapStaysBounded(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)

	const deaths = 1024
	for i := uint32(0); i < deaths; i++ {
		// Each death is a full window after the previous one, so every
		// older entry has expired by the time the next one arrives.
		at := defaulTime + uint64(i)*2*groupDeadDedupWindowNs
		el.processRawEvent(makeProcessExitEvent(t, at, 1000+i, 1000+i), out)
	}

	if el.numGroupDeadExits != deaths {
		t.Fatalf("numGroupDeadExits = %d, want %d", el.numGroupDeadExits, deaths)
	}
	if got := el.recentGroupDead.live(); got != 1 {
		t.Fatalf("recentGroupDead remembers %d deaths, want 1 (only the latest is inside the window)", got)
	}
	if got := len(el.recentGroupDead.last); got != 1 {
		t.Fatalf("recentGroupDead map holds %d pids, want 1", got)
	}
	if got := cap(el.recentGroupDead.queue); got > 4*groupDeadDedupCompactMin {
		t.Fatalf("recentGroupDead queue capacity %d grew with the number of deaths", got)
	}
}

// TestGroupDeadDedupBurstWithinOneWindow covers a burst of far more distinct
// pids than any fixed threshold inside a single window (the case the first
// implementation handled by rescanning its whole map on every death): every
// death counts, repeats of any of them are still recognised, and everything is
// released once the window has passed.
func TestGroupDeadDedupBurstWithinOneWindow(t *testing.T) {
	var d groupDeadDedup
	const burst = 10_000
	base := uint64(defaulTime)

	// All inside 50ms: 5us apart.
	for i := uint32(0); i < burst; i++ {
		if d.seen(i, base+uint64(i)*5_000) {
			t.Fatalf("first death of pid %d reported as a duplicate", i)
		}
	}
	if d.live() != burst || len(d.last) != burst {
		t.Fatalf("live = %d, map = %d, want %d each (all inside the window)", d.live(), len(d.last), burst)
	}
	// Repeats of the earliest and the latest pid within the window.
	if !d.seen(0, base+burst*5_000) || !d.seen(burst-1, base+burst*5_000) {
		t.Fatal("a repeat inside the window was counted as a new death")
	}

	// One death well after the window expires the whole burst.
	late := base + 10*groupDeadDedupWindowNs
	if d.seen(burst+1, late) {
		t.Fatal("death of a new pid reported as a duplicate")
	}
	if d.live() != 1 || len(d.last) != 1 {
		t.Fatalf("live = %d, map = %d after the window passed, want 1 each", d.live(), len(d.last))
	}
	// A recycled pid from the burst counts again.
	if d.seen(0, late+1) {
		t.Fatal("recycled pid death after the window reported as a duplicate")
	}
}

// TestGroupDeadDedupRecycledPidSurvivesOldQueueEntry guards the expiry's
// delete condition: a pid counted, expired-by-time but re-counted, has two
// queue entries, and popping the old one must not delete the newer map entry.
func TestGroupDeadDedupRecycledPidSurvivesOldQueueEntry(t *testing.T) {
	var d groupDeadDedup
	base := uint64(defaulTime)
	d.seen(7, base)
	// Same pid again just past the window, arriving as a new death; the older
	// queue entry is expired by this very call.
	second := base + groupDeadDedupWindowNs + 1
	if d.seen(7, second) {
		t.Fatal("recycled pid reported as duplicate")
	}
	if !d.seen(7, second+1) {
		t.Fatal("repeat of the recycled pid's death was counted again: its map entry was lost")
	}
}

// TestGroupDeadDedupOutOfOrderArrival keeps the semantics of records that
// arrive out of time order: an earlier record after a later one is still a
// repeat within the window, and a far-earlier one is a distinct death.
func TestGroupDeadDedupOutOfOrderArrival(t *testing.T) {
	var d groupDeadDedup
	base := uint64(defaulTime) + 10*groupDeadDedupWindowNs
	d.seen(1, base)
	if !d.seen(1, base-1_000) {
		t.Fatal("slightly older record of the same death not treated as a repeat")
	}
	if d.seen(1, base-5*groupDeadDedupWindowNs) {
		t.Fatal("record far older than the window treated as a repeat")
	}
}

// TestGroupDeadDedupSteadyStreamCompactsWhileLive drives compact() while live
// entries remain: at 20us spacing and a 100ms window about 5000 entries are
// live at any moment and the head keeps overtaking both 64 and the live count,
// so the queue is repeatedly compacted with a non-empty live part. Duplicate
// detection must stay exact throughout and storage must not grow with the
// number of deaths.
func TestGroupDeadDedupSteadyStreamCompactsWhileLive(t *testing.T) {
	var d groupDeadDedup
	const (
		deaths  = 40_000
		stepNs  = 20_000
		maxLive = groupDeadDedupWindowNs/stepNs + 2
		// Doubling growth plus the compaction hysteresis allow a few times
		// the live population; growth with the death count would be 8x more.
		maxCap = 8 * maxLive
	)
	base := uint64(defaulTime)

	for i := uint32(0); i < deaths; i++ {
		now := base + uint64(i)*stepNs
		if d.seen(i, now) {
			t.Fatalf("first death of pid %d reported as a duplicate", i)
		}
		if d.live() > maxLive || len(d.last) > d.live() {
			t.Fatalf("at death %d: live = %d (max %d), map = %d", i, d.live(), maxLive, len(d.last))
		}
		if cap(d.queue) > maxCap {
			t.Fatalf("at death %d: queue capacity %d exceeds %d", i, cap(d.queue), maxCap)
		}
		// The previous pid and one from mid-window are repeats of counted
		// deaths and must be recognised, however often the queue was compacted.
		if i >= 3000 && !d.seen(i-3000, now) {
			t.Fatalf("at death %d: repeat of pid %d (60ms earlier) counted as a new death", i, i-3000)
		}
		if i > 0 && !d.seen(i-1, now) {
			t.Fatalf("at death %d: repeat of pid %d counted as a new death", i, i-1)
		}
	}
	// A pid from long ago has expired and is a new death (recycled pid).
	if d.seen(0, base+deaths*stepNs) {
		t.Fatal("pid 0, expired long ago, reported as a duplicate")
	}
}

// TestGroupDeadDedupReleasesBurstStorageWhenIdle asserts that the memory of a
// burst is handed back once the window drains, and that ordinary small
// populations keep their storage.
func TestGroupDeadDedupReleasesBurstStorageWhenIdle(t *testing.T) {
	var d groupDeadDedup
	base := uint64(defaulTime)
	const burst = 10_000
	for i := uint32(0); i < burst; i++ {
		d.seen(i, base+uint64(i)*1_000)
	}
	if cap(d.queue) < burst {
		t.Fatalf("precondition: queue capacity %d smaller than the burst", cap(d.queue))
	}

	// Still inside the window: nothing may be released.
	d.expire(base + burst*1_000)
	if d.live() != burst || d.last == nil {
		t.Fatalf("live = %d, map nil = %v inside the window, want everything kept", d.live(), d.last == nil)
	}

	// After the window the queue and the map are dropped, not just emptied.
	d.expire(base + burst*1_000 + 2*groupDeadDedupWindowNs)
	if d.live() != 0 || d.queue != nil || d.last != nil {
		t.Fatalf("after drain: live = %d, queue nil = %v, map nil = %v, want released", d.live(), d.queue == nil, d.last == nil)
	}
	// The zero-value state keeps working, including duplicate detection.
	late := base + 10*groupDeadDedupWindowNs
	if d.seen(5, late) || !d.seen(5, late+1) {
		t.Fatal("dedup misbehaves after release")
	}

	// Negative: a small population is kept for reuse rather than reallocated.
	var small groupDeadDedup
	for i := uint32(0); i < 10; i++ {
		small.seen(i, base)
	}
	small.expire(base + 2*groupDeadDedupWindowNs)
	if small.live() != 0 || cap(small.queue) == 0 || small.last == nil {
		t.Fatalf("small population: cap = %d, map nil = %v, want storage kept", cap(small.queue), small.last == nil)
	}
}

// BenchmarkGroupDeadDedupBurst measures seen() at a steady 50k deaths/s of
// distinct pids, i.e. ~5000 live entries in the window. With O(1) amortised
// expiry the cost per call is independent of that population; a full-map scan
// per call would show up here as tens of microseconds.
func BenchmarkGroupDeadDedupBurst(b *testing.B) {
	var d groupDeadDedup
	const stepNs = 20_000 // 50k deaths per second
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.seen(uint32(i), uint64(defaulTime)+uint64(i)*stepNs)
	}
}
