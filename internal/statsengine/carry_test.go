package statsengine

import (
	"reflect"
	"testing"
	"time"
)

// carryEngine returns an engine on a fake clock; step advances it.
func carryEngine() (*Engine, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	return newEngineWithClock(8, clock.Now), clock
}

// TestCarryRetentionCoversTwiceTheWishWithBucketMargin pins the arithmetic the
// guarantee rests on. (The tie to common.SelectionWishGrace is tested in
// internal/tui/common, which may import statsengine but not vice versa.)
func TestCarryRetentionCoversTwiceTheWishWithBucketMargin(t *testing.T) {
	if guaranteed := ProcessCarryRetention - carryBucket; guaranteed < ProcessCarryRetention/2 {
		t.Fatalf("guaranteed retention %s < half of %s", guaranteed, ProcessCarryRetention)
	}
	if got := int(ProcessCarryRetention/carryBucket) + 1; got > carryMaxGenerations {
		t.Fatalf("%d generations can be live at once, cap is %d", got, carryMaxGenerations)
	}
}

// TestCarryFastResetsKeepASilentProcessForTheRetention is the regression for
// count-based aging: with -resetTimer 1s (or frequent probe toggles) the old
// four-generation ring forgot a silent process after ~4s although the TUI
// looks for it for a minute, so the silent selected 8#1 reopened as 8.
func TestCarryFastResetsKeepASilentProcessForTheRetention(t *testing.T) {
	e, clock := carryEngine()
	ingestPID(e, 8, "first")
	e.RetireProcess(8)
	ingestPID(e, 8, "second") // live 8#1

	for range 90 { // 90s of 1s resets, 8#1 stays silent
		clock.Advance(time.Second)
		e.Reset()
	}
	ingestPID(e, 8, "second")
	if got, want := pidLifetimes(t, e), map[string]uint32{"8/second": 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lifetimes after 90s of 1s resets = %v, want %v", got, want)
	}
}

// TestCarryEntryOlderThanRetentionIsDropped: after the retention (plus one
// bucket, the coalescing slack) a silent PID restarts at ordinal 0 - the
// bound that keeps memory finite.
func TestCarryEntryOlderThanRetentionIsDropped(t *testing.T) {
	e, clock := carryEngine()
	ingestPID(e, 8, "first")
	e.RetireProcess(8)
	ingestPID(e, 8, "second")
	ingestPID(e, 9, "nine") // keeps the table non-empty at later resets
	e.Reset()

	for elapsed := time.Duration(0); elapsed <= ProcessCarryRetention+carryBucket; elapsed += time.Second {
		clock.Advance(time.Second)
		ingestPID(e, 9, "nine")
		e.Reset()
	}
	if _, _, ok := e.processes.carried.entry(8); ok {
		t.Fatalf("PID 8 entry survived %s, retention is %s", ProcessCarryRetention+carryBucket, ProcessCarryRetention)
	}
	ingestPID(e, 8, "reborn")
	if got, want := pidLifetimes(t, e)["8/reborn"], uint32(0); got != want {
		t.Fatalf("aged-out PID 8 reopened as ordinal %d, want %d", got, want)
	}
	// PID 9 kept speaking, so its identity was re-carried and never aged out.
	if c, _, ok := e.processes.carried.entry(9); !ok || c.next != 0 || !c.live {
		t.Fatalf("PID 9 entry = %+v (found %v), want live ordinal 0", c, ok)
	}
}

// TestCarryEntrySurvivesGuaranteedSpanForAnyResetInterval checks the
// guaranteed lower bound directly: whatever the reset interval, an entry is
// still there ProcessCarryRetention-carryBucket after its reset.
func TestCarryEntrySurvivesGuaranteedSpanForAnyResetInterval(t *testing.T) {
	guaranteed := ProcessCarryRetention - carryBucket
	for _, interval := range []time.Duration{time.Millisecond * 100, time.Second, 7 * time.Second, 30 * time.Second} {
		e, clock := carryEngine()
		ingestPID(e, 8, "p")
		e.Reset()
		for elapsed := time.Duration(0); elapsed < guaranteed; elapsed += interval {
			clock.Advance(interval)
			e.Reset()
			if _, _, ok := e.processes.carried.entry(8); !ok {
				t.Fatalf("interval %s: entry gone %s after its reset, want kept for %s", interval, elapsed+interval, guaranteed)
			}
		}
	}
}

// TestCarryMemoryBoundUnderFastResetsWithDistinctPIDs: ten thousand resets, each
// after a batch of PIDs that never return, at rates from far faster than the
// coalescing bucket to slower than the retention. Entries never exceed
// carryMaxGenerations*maxSeen, generations never exceed carryMaxGenerations, and
// every generation holds at most maxSeen entries.
func TestCarryMemoryBoundUnderFastResetsWithDistinctPIDs(t *testing.T) {
	const topN, maxSeen, perReset, resets = 4, 16, 10, 10000
	for _, interval := range []time.Duration{time.Millisecond, 10 * time.Millisecond, time.Second, 10 * time.Second, 3 * time.Minute} {
		acc := newProcessAccumulatorWithLimits(topN, maxSeen)
		now := time.Unix(1_700_000_000, 0)
		pid := uint32(0)
		for r := 0; r < resets; r++ {
			for i := 0; i < perReset; i++ {
				pid++
				ingestAcc(acc, pid)
			}
			now = now.Add(interval)
			acc = acc.carryOver(now)
			if g := acc.carried.generations(); g > carryMaxGenerations {
				t.Fatalf("interval %s reset %d: %d generations, cap %d", interval, r, g, carryMaxGenerations)
			}
			if n := acc.carried.size(); n > carryMaxGenerations*maxSeen {
				t.Fatalf("interval %s reset %d: %d entries, bound %d", interval, r, n, carryMaxGenerations*maxSeen)
			}
			for _, g := range acc.carried.gens {
				if len(g.entries) > maxSeen {
					t.Fatalf("interval %s reset %d: generation with %d entries, maxSeen %d", interval, r, len(g.entries), maxSeen)
				}
			}
		}
	}
}

// TestCarryFastResetsCoalesceInsteadOfDroppingOldTimeCoverage: a burst of
// resets (a hundred within one bucket) must not push the entry created by the
// first one out of the table, which a count-capped ring would.
func TestCarryFastResetsCoalesceInsteadOfDroppingOldTimeCoverage(t *testing.T) {
	e, clock := carryEngine()
	ingestPID(e, 8, "p")
	for i := range 100 {
		e.Reset()
		ingestPID(e, uint32(100+i), "q") // a non-empty batch every time
		clock.Advance(carryBucket / 200)
	}
	if n := e.processes.carried.generations(); n != 1 {
		t.Fatalf("%d generations after a burst inside one bucket, want 1", n)
	}
	if _, _, ok := e.processes.carried.entry(8); !ok {
		t.Fatalf("entry lost in the burst")
	}
}

// TestCarryMovesOlderGenerationsInsteadOfCopying: Engine.Reset holds the engine
// lock, so advance must cost O(this accumulator's rows), not O(carried
// entries). Structural rather than timed: the older generations must be the
// very same maps.
func TestCarryMovesOlderGenerationsInsteadOfCopying(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var table carryTable
	for i := 0; i < 3; i++ {
		table = table.advance(now.Add(time.Duration(i)*carryBucket), map[uint32]carriedLifetime{uint32(i + 1): {}}, 64)
	}
	before := append([]carryGeneration(nil), table.gens...)
	table = table.advance(now.Add(3*carryBucket), map[uint32]carriedLifetime{99: {}}, 64)
	if len(table.gens) != 4 {
		t.Fatalf("%d generations, want 4", len(table.gens))
	}
	for i, g := range before {
		if reflect.ValueOf(table.gens[i+1].entries).Pointer() != reflect.ValueOf(g.entries).Pointer() {
			t.Fatalf("generation %d was copied, want the map moved", i)
		}
	}
}

// TestCarryNewestEntryWinsAndConsumptionClearsAll: if two generations hold the
// same PID the newest is used, and consuming it removes the stale one too so
// it cannot renumber a later process.
func TestCarryNewestEntryWinsAndConsumptionClearsAll(t *testing.T) {
	acc := newProcessAccumulatorWithLimits(8, 64)
	acc.carried.gens = []carryGeneration{
		{start: time.Unix(200, 0), entries: map[uint32]carriedLifetime{8: {next: 3}}},
		{start: time.Unix(100, 0), entries: map[uint32]carriedLifetime{8: {next: 1, live: true}}},
	}
	ingestAcc(acc, 8)
	if got := acc.byPID[8].lifetime; got != 3 {
		t.Fatalf("lifetime = %d, want the newest entry's 3", got)
	}
	if n := acc.carried.size(); n != 0 {
		t.Fatalf("%d carried entries left after consumption, want 0", n)
	}
}

// TestCarryRetireOfEntryInAnOlderGeneration: the process exits (group-dead) while
// its carried entry sits in a generation older than the newest, and its
// successor must take the next ordinal. Looking only at the newest generation
// (or at gens[0]) leaves the ordinal unspent and the successor collides with
// the dead process's selection key.
func TestCarryRetireOfEntryInAnOlderGeneration(t *testing.T) {
	e, clock := carryEngine()
	ingestPID(e, 8, "first")
	e.RetireProcess(8)
	ingestPID(e, 8, "second") // live 8#1
	ingestPID(e, 9, "nine")
	e.Reset() // 8#1 is in the newest generation
	clock.Advance(carryBucket + time.Second)
	ingestPID(e, 9, "nine")
	e.Reset() // 8#1 is now in an older one, the newest holds 9
	if e.processes.carried.generations() != 2 {
		t.Fatalf("setup: %d generations, want 2", e.processes.carried.generations())
	}
	if _, m, _ := e.processes.carried.entry(8); reflect.ValueOf(m).Pointer() == reflect.ValueOf(e.processes.carried.gens[0].entries).Pointer() {
		t.Fatalf("setup: the entry of PID 8 is in the newest generation")
	}

	e.RetireProcess(8)
	ingestPID(e, 8, "third")
	if got, want := pidLifetimes(t, e)["8/third"], uint32(2); got != want {
		t.Fatalf("successor of the carried process got ordinal %d, want %d", got, want)
	}
}

// TestCarryNoWrongSuccessorWithinTheWishWindow: a silent selected process 8#0
// (wish key "8") exits while fast resets run, and its PID is recycled. The old
// count-based ring had aged the entry out by then, so RetireProcess found nothing
// to spend and the successor reopened as "8" - the process the wish was
// waiting for. With time-based aging the ordinal is spent and the successor is
// 8#1, for as long as the wish can be looking.
func TestCarryNoWrongSuccessorWithinTheWishWindow(t *testing.T) {
	e, clock := carryEngine()
	ingestPID(e, 8, "selected") // live 8#0, silent from now on
	for range 50 {              // fast resets, well inside a one-minute wish
		clock.Advance(time.Second)
		e.Reset()
	}
	e.RetireProcess(8) // the exit is observed; the entry must still be there
	ingestPID(e, 8, "successor")
	if got, want := pidLifetimes(t, e)["8/successor"], uint32(1); got != want {
		t.Fatalf("successor reopened as ordinal %d, want %d (the selected process was 8#0)", got, want)
	}
}

// TestCarryMergeKeepsNewerAndEvictsOlderOverTheLimit pins mergeCarried. The
// limit equals the number of newer entries and older holds many more, so the
// result is fully determined despite the random map iteration order: exactly
// the newer entries survive (as given, winning over an older entry of the same
// PID) and every older-only entry is evicted. A merge that also trimmed newer
// entries would drop one of them on nearly every iteration, so the loop makes
// that mutation fail reliably.
func TestCarryMergeKeepsNewerAndEvictsOlderOverTheLimit(t *testing.T) {
	const newerCount, olderOnly = 8, 200
	for iter := 0; iter < 200; iter++ {
		older := make(map[uint32]carriedLifetime)
		newer := make(map[uint32]carriedLifetime)
		for pid := uint32(1); pid <= newerCount; pid++ {
			newer[pid] = carriedLifetime{next: 9}
			if pid%2 == 0 { // half of the newer PIDs also exist in older
				older[pid] = carriedLifetime{next: 1}
			}
		}
		for pid := uint32(1000); pid < 1000+olderOnly; pid++ {
			older[pid] = carriedLifetime{next: 1}
		}
		mergeCarried(older, newer, newerCount)
		if len(older) != newerCount {
			t.Fatalf("iteration %d: %d entries after merge, want the limit %d", iter, len(older), newerCount)
		}
		for pid, want := range newer {
			if got, ok := older[pid]; !ok || got != want {
				t.Fatalf("iteration %d: newer entry %d = %+v (present %v), want %+v", iter, pid, got, ok, want)
			}
		}
	}
}

// BenchmarkEngineResetWithFullCarryTable shows Reset costs O(own rows), with the
// carried table at its bound (carryMaxGenerations generations of maxSeen
// entries): the older generations are moved, not copied.
func BenchmarkEngineResetWithFullCarryTable(b *testing.B) {
	e, clock := carryEngine()
	maxSeen := e.processes.maxSeen
	for g := 0; g < carryMaxGenerations; g++ {
		for i := 0; i < maxSeen; i++ {
			ingestPID(e, uint32(g*maxSeen+i+1), "p")
		}
		clock.Advance(carryBucket)
		e.Reset()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Reset()
	}
}
