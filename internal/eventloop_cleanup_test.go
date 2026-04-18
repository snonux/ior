package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

func TestTracepointEnteredPrunesOldestPendingPairs(t *testing.T) {
	el := &eventLoop{
		commResolver: newCommResolver(make(map[uint32]string)),
		pairs:        pairTracker{maxSize: 2},
	}

	enterOne, _ := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	enterTwo, _ := makeEnterOpenEvent(t, defaulTime+1, defaultPid, defaultTid+1)
	enterThree, _ := makeEnterOpenEvent(t, defaulTime+2, defaultPid, defaultTid+2)

	el.tracepointEntered(&enterOne)
	el.tracepointEntered(&enterTwo)
	el.tracepointEntered(&enterThree)

	if _, ok := el.pairs.enters[defaultTid]; ok {
		t.Fatalf("expected oldest pending enter event to be evicted")
	}
	if _, ok := el.pairs.enters[defaultTid+1]; !ok {
		t.Fatalf("expected newer pending enter event to be retained")
	}
	if _, ok := el.pairs.enters[defaultTid+2]; !ok {
		t.Fatalf("expected newest pending enter event to be retained")
	}
	if got := len(el.pairs.enterAges); got != 2 {
		t.Fatalf("pending enter metadata size = %d, want 2", got)
	}

	for _, pair := range el.pairs.enters {
		pair.Recycle()
	}
}

func TestConsumeEnterEventClearsPendingPairMetadata(t *testing.T) {
	el := &eventLoop{}

	enterOne, _ := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	el.pairs.set(&enterOne)

	pair, ok := el.pairs.consume(defaultTid)
	if !ok {
		t.Fatalf("expected pending enter event to be consumed")
	}
	if pair == nil {
		t.Fatalf("expected consumed pair")
	}
	pair.Recycle()

	if _, ok := el.pairs.enters[defaultTid]; ok {
		t.Fatalf("expected pending enter pair to be removed")
	}
	if _, ok := el.pairs.enterAges[defaultTid]; ok {
		t.Fatalf("expected pending enter metadata to be removed")
	}
}

func TestProcFdCacheRetainsRecentlyUsedEntries(t *testing.T) {
	fdt := newFDTracker(nil)
	fdt.maxCacheSize = 2
	el := &eventLoop{fdTracker: fdt}

	el.fdTracker.setProcFdCache(10, defaultPid, file.NewFdWithPid(10, defaultPid))
	el.fdTracker.setProcFdCache(11, defaultPid, file.NewFdWithPid(11, defaultPid))

	if _, ok := el.fdTracker.cachedProcFdFile(10, defaultPid); !ok {
		t.Fatalf("expected first cache entry to exist before refresh")
	}

	el.fdTracker.setProcFdCache(12, defaultPid, file.NewFdWithPid(12, defaultPid))

	if _, ok := el.fdTracker.cachedProcFdFile(10, defaultPid); !ok {
		t.Fatalf("expected recently used cache entry to be retained")
	}
	if _, ok := el.fdTracker.cachedProcFdFile(11, defaultPid); ok {
		t.Fatalf("expected least recently used cache entry to be evicted")
	}
	if _, ok := el.fdTracker.cachedProcFdFile(12, defaultPid); !ok {
		t.Fatalf("expected newest cache entry to be retained")
	}
	if got := len(el.fdTracker.procFdAges); got != 2 {
		t.Fatalf("proc fd cache metadata size = %d, want 2", got)
	}
}

func TestPendingHandleTrackerRetainsRecentlyUsedEntries(t *testing.T) {
	tracker := newPendingHandleTracker()
	tracker.maxCacheSize = 2

	tracker.set(defaultTid, "/tmp/handle-one")
	tracker.set(defaultTid+1, "/tmp/handle-two")
	tracker.set(defaultTid+2, "/tmp/handle-three")

	if _, ok := tracker.paths[defaultTid]; ok {
		t.Fatalf("expected oldest pending handle to be evicted")
	}
	if _, ok := tracker.paths[defaultTid+1]; !ok {
		t.Fatalf("expected newer pending handle to be retained")
	}
	if _, ok := tracker.paths[defaultTid+2]; !ok {
		t.Fatalf("expected newest pending handle to be retained")
	}
	if got := len(tracker.pathAges); got != 2 {
		t.Fatalf("pending handle metadata size = %d, want 2", got)
	}
}

func TestOpenByHandleAtFailureClearsPendingHandle(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	_, enterNameRaw := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, "/tmp/handle.txt", types.SYS_ENTER_NAME_TO_HANDLE_AT)
	el.tracepointEntered(types.NewPathEvent(enterNameRaw))
	_, exitNameRaw := makeExitRetEvent(t, defaulTime+1, defaultPid, defaultTid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	el.tracepointExited(types.NewRetEvent(exitNameRaw), make(chan *event.Pair, 1))

	_, enterOpenRaw := makeEnterOpenByHandleAtEvent(t, defaulTime+2, defaultPid, defaultTid, 0)
	el.tracepointEntered(types.NewOpenByHandleAtEvent(enterOpenRaw))
	_, exitOpenRaw := makeExitRetEvent(t, defaulTime+3, defaultPid, defaultTid, types.SYS_EXIT_OPEN_BY_HANDLE_AT, -1)
	el.tracepointExited(types.NewRetEvent(exitOpenRaw), make(chan *event.Pair, 1))

	if _, ok := el.pendingHandleState().paths[defaultTid]; ok {
		t.Fatalf("expected pending handle to be cleared after failed open_by_handle_at")
	}
}
