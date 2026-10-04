package internal

import (
	"errors"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// restartPendingMapName is the ARRAY of per-task restart state declared in
// internal/c/maps.h: one __u64 word per slot, 0 for a free slot
// (internal/c/restart.c).
const restartPendingMapName = "restart_pending_map"

// restartPendingSlotMap is the write surface of restart_pending_map that
// clearing it needs, so tests can exercise the clear without a live BPF
// module.
type restartPendingSlotMap interface {
	MaxEntries() uint32
	Update(key, value unsafe.Pointer) error
	UpdateBatch(keys, values unsafe.Pointer, count uint32) (uint32, error)
}

// restartPendingClearer forgets every pending restart BPF tracks. The event
// loop asks for it when a syscall's probes are attached or detached at
// runtime (eventLoop.probesChanged, task o03); stubbed in tests.
type restartPendingClearer interface {
	Clear() error
}

// restartPendingMap clears the kernel's restart_pending_map from userspace.
type restartPendingMap struct {
	slots restartPendingSlotMap
}

// newRestartPendingMap opens restart_pending_map of a loaded BPF module.
func newRestartPendingMap(module *bpf.Module) (*restartPendingMap, error) {
	if module == nil {
		return nil, errors.New("nil bpf module")
	}
	slots, err := module.GetMap(restartPendingMapName)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", restartPendingMapName, err)
	}
	return &restartPendingMap{slots: slots}, nil
}

// Clear writes 0, the free-slot word, to every slot of the map.
//
// One batch update does it where the kernel has batch operations for ARRAY
// maps (5.6 and later); it is one bpf(2) call where the per-slot fallback
// makes max_entries of them (4096), and a family toggle in the TUI clears once
// per probe. A batch the kernel refuses or cuts short is followed by the
// per-slot pass, which reports the first slot that could not be written and
// still tries the rest: a partial clear is worth more than none.
//
// It races with the BPF programs, which run on other CPUs meanwhile, and that
// is harmless. A handler that stores a new entry right after its slot was
// cleared has made a call pending that was interrupted after the clear, which
// is exactly what must stay. A handler that read a slot before the clear and
// writes it back changed afterwards (the handler depth of a delivered signal
// or an rt_sigreturn, restart.c) keeps one entry alive; that entry announces
// nothing userspace folds, because the loop also refuses, by time, every row
// interrupted before the probe change that asked for this clear
// (restartProbeWatch.changedSince, asked by restartTracker.holdable when a row
// is to be held and by eventLoop.restartAcrossProbeChange when one is to be
// folded). The clear and that rule each cover the other's gap; see "Runtime
// probe changes" in eventloop_restart.go.
//
// The key and value slices are built anew on every call, 48 KiB that live for
// one bpf(2) call. Clear runs on the goroutine that changes a probe, under
// that probe's attach mutex only, so two probes changed at once (the TUI runs
// every toggle as its own command) clear concurrently. Slices kept on the map
// would be shared between those calls and handed to cgo by both; the kernel
// only reads them, but nothing in the slot-map interface says so, and a probe
// change is far too rare for the allocation to matter.
func (m *restartPendingMap) Clear() error {
	if m == nil || m.slots == nil {
		return nil
	}
	count := m.slots.MaxEntries()
	if count == 0 {
		return nil
	}
	keys := make([]uint32, count)
	for i := range keys {
		keys[i] = uint32(i)
	}
	values := make([]uint64, count)
	done, err := m.slots.UpdateBatch(unsafe.Pointer(&keys[0]), unsafe.Pointer(&values[0]), count)
	if err == nil && done == count {
		return nil
	}
	return m.clearSlotBySlot(keys)
}

// clearSlotBySlot is the fallback of Clear: one update per slot. It returns
// the first failure after trying every slot.
func (m *restartPendingMap) clearSlotBySlot(keys []uint32) error {
	var (
		free  uint64
		first error
	)
	for i := range keys {
		if err := m.slots.Update(unsafe.Pointer(&keys[i]), unsafe.Pointer(&free)); err != nil && first == nil {
			first = fmt.Errorf("clear %s slot %d: %w", restartPendingMapName, keys[i], err)
		}
	}
	return first
}
