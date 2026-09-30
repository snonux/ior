package statsengine

import "time"

// ProcessCarryRetention is how long Engine.Reset remembers the lifetime ordinal
// of a process that stays silent: an entry is dropped once it is older than
// this, measured on the engine's clock from the reset that created it (or, for
// entries coalesced into a shared generation, from the first reset of that
// generation, see carryBucket).
//
// The TUI keeps looking for a selected process for common.SelectionWishGrace
// after the reset that emptied the table. The entry must outlive that wish, or
// a silent selected process "8#1" would reopen as "8", never match the wish,
// and - if a successor of a process that held PID 8 as ordinal 0 recycles the
// PID after the old entry aged out unobserved - the wish for "8" could land on
// the wrong process. Twice the grace leaves the margin for the coalescing loss
// of carryBucket. internal/tui/common pins ProcessCarryRetention >=
// 2*SelectionWishGrace with a test; statsengine cannot import that package
// (the dependency points the other way), so the value lives here.
//
// Time, not the number of resets, sets the retention on purpose: -resetTimer
// accepts any positive duration and probe toggles, filter swaps and the r key
// reset too, so a count-based limit would forget the entry after seconds while
// the wish is still looking for it.
const ProcessCarryRetention = 2 * time.Minute

const (
	// carryMaxGenerations caps the number of generations, and with it the
	// per-lookup work (one map probe per generation) and the slice overhead.
	carryMaxGenerations = 16
	// carryBucket is the time span one generation covers. Resets closer than
	// this to the start of the newest generation are coalesced into it instead
	// of opening another one, so the retention window is never shortened to
	// fit the cap: at most ProcessCarryRetention/carryBucket+1 = 16 generations
	// are ever live. An entry therefore survives at least ProcessCarryRetention
	// - carryBucket (112s with the values above) after its reset.
	carryBucket = ProcessCarryRetention / (carryMaxGenerations - 1)
)

// carriedLifetime is one PID's ordinal across an accumulator swap.
type carriedLifetime struct {
	// next is the ordinal the PID's next row gets.
	next uint32
	// live is true while the process that held ordinal next is presumed to
	// still run: the old accumulator had a live row for it and no group
	// exit has been seen since. RetireProcess then spends the ordinal by
	// advancing next.
	live bool
}

// carryGeneration holds the entries of one or more consecutive resets.
type carryGeneration struct {
	// start is the engine-clock time of the first reset merged into the
	// generation; the whole generation expires ProcessCarryRetention after it.
	start time.Time
	// entries has at most maxSeen items (see mergeCarried), like the single
	// batch one carryOver builds from an accumulator's own rows.
	entries map[uint32]carriedLifetime
}

// carryTable is the set of carried ordinals that survives Engine.Reset: a list
// of generations, newest first, with strictly decreasing start times.
//
// Memory is bounded by carryMaxGenerations*maxSeen entries whatever the reset
// rate or the number of PIDs ever seen (on a box churning short-lived
// processes only pid_max, up to 4M, would bound a table with one entry per
// PID, at hundreds of MB): each generation holds at most maxSeen entries and
// there are at most carryMaxGenerations of them. Resets that come in faster
// than one per carryBucket are coalesced into the newest generation, so a
// burst of resets loses no time coverage. When a coalesced generation would
// exceed maxSeen entries, the older entries make room (mergeCarried); that
// only costs stickiness for PIDs that were silent across more than maxSeen
// other PIDs' worth of resets within one bucket.
//
// The zero value is an empty table.
type carryTable struct {
	gens []carryGeneration
}

// advance returns the table after a reset at now: expired generations are
// dropped, and newest (the entries the resetting accumulator built from its own
// rows, at most limit) is coalesced into the newest generation if that one is
// younger than carryBucket, otherwise it becomes a new generation. Older
// generations are moved, never copied: Engine.Reset calls this under the
// engine lock, so its cost must depend on len(newest) and limit only, not on
// the size of the table. The receiver must not be used afterwards.
func (t carryTable) advance(now time.Time, newest map[uint32]carriedLifetime, limit int) carryTable {
	gens := t.gens
	for n := len(gens); n > 0 && now.Sub(gens[n-1].start) > ProcessCarryRetention; n-- {
		gens[n-1] = carryGeneration{} // do not pin the dropped map in the backing array
		gens = gens[:n-1]
	}
	if len(newest) == 0 {
		return carryTable{gens: gens}
	}
	if len(gens) > 0 && now.Sub(gens[0].start) < carryBucket {
		mergeCarried(gens[0].entries, newest, limit)
		return carryTable{gens: gens}
	}
	out := make([]carryGeneration, 0, len(gens)+1)
	out = append(out, carryGeneration{start: now, entries: newest})
	out = append(out, gens...)
	// Unreachable while start times are spaced >= carryBucket within the
	// retention window; kept for a clock that jumps backwards. Coalescing keeps
	// the older start, so nothing expires later than it would have.
	for len(out) > carryMaxGenerations {
		last := out[len(out)-1]
		mergeCarried(last.entries, out[len(out)-2].entries, limit)
		out = out[:len(out)-1]
		out[len(out)-1] = last
	}
	return carryTable{gens: out}
}

// mergeCarried adds the entries of newer to older, newer winning on a PID both
// hold, and then evicts entries of older that newer does not hold until at most
// limit remain. Iteration order is random, so which of the older entries go is
// arbitrary; newer is never trimmed, it is the fresher information.
func mergeCarried(older, newer map[uint32]carriedLifetime, limit int) {
	for pid, c := range newer {
		older[pid] = c
	}
	for pid := range older {
		if len(older) <= limit {
			return
		}
		if _, fresh := newer[pid]; !fresh {
			delete(older, pid)
		}
	}
}

// entry returns the newest entry of pid and the generation map holding it.
func (t carryTable) entry(pid uint32) (carriedLifetime, map[uint32]carriedLifetime, bool) {
	for _, g := range t.gens {
		if c, ok := g.entries[pid]; ok {
			return c, g.entries, true
		}
	}
	return carriedLifetime{}, nil, false
}

// take returns the newest entry of pid and removes the PID from every
// generation, so an older, stale entry cannot resurface once the newest one is
// consumed by the row that opens.
func (t carryTable) take(pid uint32) (carriedLifetime, bool) {
	c, _, ok := t.entry(pid)
	if !ok {
		return carriedLifetime{}, false
	}
	for _, g := range t.gens {
		delete(g.entries, pid)
	}
	return c, true
}

// spend records that the carried process of pid exited before it issued a
// syscall in the new accumulator (so there is no row to retire): its ordinal is
// used up and the PID's next process takes the following one. Entries that are
// not live (their process already exited) or missing are left alone, which
// makes a duplicate exit record harmless.
func (t carryTable) spend(pid uint32) {
	if c, entries, ok := t.entry(pid); ok && c.live {
		entries[pid] = carriedLifetime{next: c.next + 1}
	}
}

// generations is the number of generations held.
func (t carryTable) generations() int { return len(t.gens) }

// size is the total number of entries over all generations.
func (t carryTable) size() int {
	n := 0
	for _, g := range t.gens {
		n += len(g.entries)
	}
	return n
}
