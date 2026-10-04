package internal

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

// Tests for clearing restart_pending_map (restartPendingMap.Clear, task o03)
// against a fake map: the real one needs a loaded BPF object. The fake holds
// a non-zero word in every slot, as if every slot had a pending task.

// fakeRestartSlots is restart_pending_map as Clear writes it.
type fakeRestartSlots struct {
	slots []uint64
	// batchErr fails UpdateBatch (a kernel without batch operations for ARRAY
	// maps); batchDone, when not zero, cuts a successful batch short.
	batchErr  error
	batchDone uint32
	// failSlots are the slots whose single update fails.
	failSlots map[uint32]error
	batches   int
	updates   int
}

func newFakeRestartSlots(n int) *fakeRestartSlots {
	slots := make([]uint64, n)
	for i := range slots {
		slots[i] = 0x1_0000_1000 | uint64(i) // a pending word: code 1 and a tid
	}
	return &fakeRestartSlots{slots: slots}
}

func (m *fakeRestartSlots) MaxEntries() uint32 { return uint32(len(m.slots)) }

func (m *fakeRestartSlots) Update(key, value unsafe.Pointer) error {
	m.updates++
	slot := *(*uint32)(key)
	if err := m.failSlots[slot]; err != nil {
		return err
	}
	m.slots[slot] = *(*uint64)(value)
	return nil
}

func (m *fakeRestartSlots) UpdateBatch(keys, values unsafe.Pointer, count uint32) (uint32, error) {
	m.batches++
	if m.batchErr != nil {
		return 0, m.batchErr
	}
	done := count
	if m.batchDone != 0 {
		done = m.batchDone
	}
	keySlice, valueSlice := unsafe.Slice((*uint32)(keys), count), unsafe.Slice((*uint64)(values), count)
	for i := range done {
		m.slots[keySlice[i]] = valueSlice[i]
	}
	return done, nil
}

// pendingSlots returns the slots that still hold a pending word.
func (m *fakeRestartSlots) pendingSlots() []int {
	var pending []int
	for slot, word := range m.slots {
		if word != 0 {
			pending = append(pending, slot)
		}
	}
	return pending
}

// TestRestartPendingMapClearFreesEverySlot: one batch update writes the
// free-slot word to every slot, and no per-slot update follows it.
func TestRestartPendingMapClearFreesEverySlot(t *testing.T) {
	slots := newFakeRestartSlots(4096)
	if err := (&restartPendingMap{slots: slots}).Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if pending := slots.pendingSlots(); len(pending) != 0 {
		t.Fatalf("%d slots still pending after Clear, first %d", len(pending), pending[0])
	}
	if slots.batches != 1 || slots.updates != 0 {
		t.Fatalf("batches=%d single updates=%d, want one batch and no single update", slots.batches, slots.updates)
	}
}

// TestRestartPendingMapClearFallsBackToSingleUpdates: a kernel that has no
// batch update for ARRAY maps (before 5.6), or one that cuts the batch short,
// must not leave entries standing: every slot is then written on its own.
func TestRestartPendingMapClearFallsBackToSingleUpdates(t *testing.T) {
	for name, arrange := range map[string]func(*fakeRestartSlots){
		"batch refused":   func(m *fakeRestartSlots) { m.batchErr = errors.New("invalid argument") },
		"batch cut short": func(m *fakeRestartSlots) { m.batchDone = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			slots := newFakeRestartSlots(64)
			arrange(slots)
			if err := (&restartPendingMap{slots: slots}).Clear(); err != nil {
				t.Fatalf("Clear() error = %v, want the fallback to succeed", err)
			}
			if pending := slots.pendingSlots(); len(pending) != 0 {
				t.Fatalf("slots %v still pending after the fallback", pending)
			}
			if slots.updates != 64 {
				t.Fatalf("single updates = %d, want one per slot (64)", slots.updates)
			}
		})
	}
}

// TestRestartPendingMapClearReportsAFailedSlotAndClearsTheRest: a slot that
// cannot be written is reported - the first one, by number - and every other
// slot is still cleared: fewer stale entries is better than giving up.
func TestRestartPendingMapClearReportsAFailedSlotAndClearsTheRest(t *testing.T) {
	slots := newFakeRestartSlots(16)
	slots.batchErr = errors.New("invalid argument")
	slots.failSlots = map[uint32]error{5: errors.New("permission denied"), 9: errors.New("later failure")}

	err := (&restartPendingMap{slots: slots}).Clear()
	if err == nil || !strings.Contains(err.Error(), "slot 5") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Clear() error = %v, want the first failed slot (5) and its cause", err)
	}
	if pending := slots.pendingSlots(); len(pending) != 2 || pending[0] != 5 || pending[1] != 9 {
		t.Fatalf("slots still pending = %v, want only the two that failed (5, 9)", pending)
	}
}

// TestRestartPendingMapClearWithoutAMap: a nil clearer, one without a map and
// an empty map have nothing to clear and report no error; a nil module has no
// map to open.
func TestRestartPendingMapClearWithoutAMap(t *testing.T) {
	var none *restartPendingMap
	for name, pending := range map[string]*restartPendingMap{
		"nil": none, "no map": {}, "empty map": {slots: newFakeRestartSlots(0)},
	} {
		if err := pending.Clear(); err != nil {
			t.Fatalf("%s: Clear() error = %v, want nil", name, err)
		}
	}
	if pending, err := newRestartPendingMap(nil); err == nil || pending != nil {
		t.Fatalf("newRestartPendingMap(nil) = %v, %v; want an error and no clearer", pending, err)
	}
	// The loop tests the interface for nil: a failed open must leave it a true
	// nil, not a nil *restartPendingMap inside a non-nil interface.
	el := &eventLoop{}
	attachRestartPendingMap(el, nil)
	if el.restartPending != nil {
		t.Fatalf("attachRestartPendingMap without a module left a clearer behind: %#v", el.restartPending)
	}
}
