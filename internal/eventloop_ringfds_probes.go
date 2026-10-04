package internal

import (
	"sync/atomic"

	"ior/internal/probemanager"
)

// ringProbeWatch fences registered-ring knowledge across runtime gaps in its
// capture probes. Hooks only publish atomics; tables belong to the loop.
// Unlike restart folding, unrelated syscall toggles do not affect this mirror.
type ringProbeWatch struct {
	inFlight  atomic.Int64
	changedAt atomic.Uint64
	detached  atomic.Bool
	// appliedAt is owned exclusively by the event-loop goroutine.
	appliedAt uint64
}

func (w *ringProbeWatch) note(at uint64) {
	for {
		seen := w.changedAt.Load()
		if at <= seen || w.changedAt.CompareAndSwap(seen, at) {
			return
		}
	}
}

// noteRingProbeChange runs on the manager's goroutine. Publish the attach's
// final stamp before lowering its count, as restartProbeWatch does: records
// captured between the two link attachments are unsafe even after completion.
// The ordinary restart notification wakes the loop after these stores.
// Detach is reported only after both links are destroyed; this guard starts
// at that report, not during the preceding teardown.
func (e *eventLoop) noteRingProbeChange(change probemanager.Change) {
	if change.Syscall != "io_uring_register" {
		return
	}
	w := &e.ringProbes
	if change.Phase == probemanager.ChangeBegins {
		w.inFlight.Add(1)
	} else {
		w.detached.Store(!change.Attached)
	}
	w.note(e.readDropStampClock())
	if change.Phase == probemanager.ChangeEnds {
		w.inFlight.Add(-1)
	}
}

// applyRingProbeChanges must run both on wake and on the record path: a ready
// raw channel can beat the notification in select, including during shutdown
// draining. Checking again when resolving a slot also covers a hook that ran
// while the record's handler was working.
func (e *eventLoop) applyRingProbeChanges() {
	w := &e.ringProbes
	changing := w.inFlight.Load() > 0
	at := w.changedAt.Load()
	if changing || w.detached.Load() || at != w.appliedAt {
		if e.rings != nil {
			e.rings.dropAll()
		}
		w.appliedAt = at
	}
}

func (e *eventLoop) ringRecordAcrossProbeChange(at uint64) bool {
	w := &e.ringProbes
	if w.inFlight.Load() > 0 || w.detached.Load() {
		return true
	}
	changedAt := w.changedAt.Load()
	return changedAt != 0 && at <= changedAt
}
