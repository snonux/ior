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
	d.compact()
}

// compact reclaims the consumed prefix of the queue once it is at least as
// large as the live part, which keeps the copying amortised O(1) per pop and
// the backing array proportional to the live entries.
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
