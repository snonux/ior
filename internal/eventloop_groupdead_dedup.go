package internal

// groupDeadDedupWindowNs is how close (in kernel boot-clock nanoseconds) two
// group-dead records of one pid must be to count as the same process death.
// The duplicates come from threads of one exit_group racing through do_exit()
// within microseconds of each other; 100ms leaves ample slack for ring-buffer
// reordering across CPUs while staying far below the time a pid takes to be
// recycled and die again.
const groupDeadDedupWindowNs = 100_000_000

// groupDeadDedupCompactMin is the smallest number of consumed queue slots
// worth reclaiming; below it the copy would cost more than the memory saves.
const groupDeadDedupCompactMin = 64

// groupDeadDedupReleaseCap is the queue capacity (in entries) above which the
// storage is handed back to the garbage collector once the dedup goes idle.
// It is far above the population of a normal trace (a few hundred deaths per
// window), so ordinary operation keeps and reuses its backing array and only a
// one-off burst pays for a reallocation.
const groupDeadDedupReleaseCap = 1024

// groupDeadEntry is one counted process death: the pid and the boot-clock
// time of the record that was counted.
type groupDeadEntry struct {
	time uint64
	pid  uint32
}

// groupDeadDedup remembers recently counted process deaths so the repeated
// group-dead records that old kernels can produce for one death (see
// isDuplicateGroupDead) are recognised. The zero value is ready to use.
//
// Entries expire incrementally: queue holds them in arrival order and every
// call pops the expired ones off the front, so a call costs O(1) amortised
// however many pids died inside one window. An earlier version pruned by
// scanning the whole map once it passed a size threshold; under a burst of
// more pids than that threshold within one window nothing was expired, so
// every later death rescanned the whole map on the event-loop goroutine. Both
// structures are now bounded by the deaths seen within one window.
//
// The bound is on the live entries, not on the storage: a slice never shrinks
// and neither does a Go map's bucket array, so after a burst of N pids in one
// window the queue capacity and the map buckets stay at N-sized for as long as
// deaths keep arriving inside each other's windows. Once the window has drained
// completely (see release) an oversized queue and the map are dropped, so the
// memory of a burst is returned as soon as the process-death rate calms down.
//
// Records may arrive slightly out of time order (different CPUs), so the queue
// is only approximately sorted by time. Expiry stops at the first entry still
// inside the window, so an entry stuck behind a slightly newer one lingers
// until that one expires as well: a delay bounded by the reordering skew, not
// a leak, and it never causes a wrong answer because duplicate detection
// looks at the recorded time, not at queue membership.
//
// Event-loop goroutine only.
type groupDeadDedup struct {
	// last maps a pid to the boot-clock time of its most recent counted death.
	last map[uint32]uint64
	// queue holds counted deaths in arrival order; queue[head:] is live, the
	// slots before head are consumed and reclaimed lazily by compact.
	queue []groupDeadEntry
	head  int
}

// seen reports whether a death of pid at time now repeats one already counted
// and, when it does not, records it. Expiry runs first, relative to now.
func (d *groupDeadDedup) seen(pid uint32, now uint64) bool {
	d.expire(now)
	if last, ok := d.last[pid]; ok && absDiffNs(last, now) <= groupDeadDedupWindowNs {
		return true
	}
	if d.last == nil {
		d.last = make(map[uint32]uint64)
	}
	d.last[pid] = now
	d.queue = append(d.queue, groupDeadEntry{time: now, pid: pid})
	return false
}

// expire pops entries that are older than the window relative to now off the
// front of the queue and drops their map entries. A pid re-counted after its
// window has a newer map entry (and a newer queue entry behind this one), so
// the map entry is only deleted when it still carries the popped time.
func (d *groupDeadDedup) expire(now uint64) {
	for d.head < len(d.queue) {
		e := d.queue[d.head]
		if e.time >= now || now-e.time <= groupDeadDedupWindowNs {
			break
		}
		if d.last[e.pid] == e.time {
			delete(d.last, e.pid)
		}
		d.head++
	}
	if d.live() == 0 {
		d.release()
		return
	}
	d.compact()
}

// release is called when nothing is remembered any more. It rewinds the queue
// for reuse, and when a burst had grown the queue past groupDeadDedupReleaseCap
// it drops the queue and the map instead: the map is empty at this point (every
// map entry has a queue entry carrying the same time, and all of those were
// popped) but keeps its burst-sized bucket array, which only replacing it can
// give back. Normal-sized storage is kept so a steady trace never reallocates.
func (d *groupDeadDedup) release() {
	if cap(d.queue) > groupDeadDedupReleaseCap {
		d.queue = nil
		d.last = nil
	} else {
		d.queue = d.queue[:0]
	}
	d.head = 0
}

// compact reclaims the consumed prefix of the queue once it is at least as
// large as the live part, which keeps the copying amortised O(1) per pop and
// keeps the backing array within a constant factor of the largest live
// population seen since the dedup was last idle (see release), not of the
// number of deaths seen overall.
func (d *groupDeadDedup) compact() {
	if d.head < groupDeadDedupCompactMin || d.head < len(d.queue)-d.head {
		return
	}
	n := copy(d.queue, d.queue[d.head:])
	d.queue = d.queue[:n]
	d.head = 0
}

// live returns the number of deaths currently remembered.
func (d *groupDeadDedup) live() int {
	return len(d.queue) - d.head
}

// absDiffNs returns |a-b| for unsigned nanosecond timestamps.
func absDiffNs(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
