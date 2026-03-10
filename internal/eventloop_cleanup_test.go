package internal

import (
	"testing"

	"ior/internal/file"
)

func TestTracepointEnteredPrunesOldestPendingPairs(t *testing.T) {
	el := &eventLoop{
		commResolver:       newCommResolver(make(map[uint32]string)),
		maxPendingEnterEvs: 2,
	}

	enterOne, _ := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	enterTwo, _ := makeEnterOpenEvent(t, defaulTime+1, defaultPid, defaultTid+1)
	enterThree, _ := makeEnterOpenEvent(t, defaulTime+2, defaultPid, defaultTid+2)

	el.tracepointEntered(&enterOne)
	el.tracepointEntered(&enterTwo)
	el.tracepointEntered(&enterThree)

	if _, ok := el.enterEvs[defaultTid]; ok {
		t.Fatalf("expected oldest pending enter event to be evicted")
	}
	if _, ok := el.enterEvs[defaultTid+1]; !ok {
		t.Fatalf("expected newer pending enter event to be retained")
	}
	if _, ok := el.enterEvs[defaultTid+2]; !ok {
		t.Fatalf("expected newest pending enter event to be retained")
	}
	if got := len(el.enterEvAges); got != 2 {
		t.Fatalf("pending enter metadata size = %d, want 2", got)
	}

	for _, pair := range el.enterEvs {
		pair.Recycle()
	}
}

func TestConsumeEnterEventClearsPendingPairMetadata(t *testing.T) {
	el := &eventLoop{}

	enterOne, _ := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	el.setEnterEvent(&enterOne)

	pair, ok := el.consumeEnterEvent(defaultTid)
	if !ok {
		t.Fatalf("expected pending enter event to be consumed")
	}
	if pair == nil {
		t.Fatalf("expected consumed pair")
	}
	pair.Recycle()

	if _, ok := el.enterEvs[defaultTid]; ok {
		t.Fatalf("expected pending enter pair to be removed")
	}
	if _, ok := el.enterEvAges[defaultTid]; ok {
		t.Fatalf("expected pending enter metadata to be removed")
	}
}

func TestProcFdCacheRetainsRecentlyUsedEntries(t *testing.T) {
	el := &eventLoop{maxProcFdCacheSize: 2}

	el.setProcFdCache(10, defaultPid, file.NewFdWithPid(10, defaultPid))
	el.setProcFdCache(11, defaultPid, file.NewFdWithPid(11, defaultPid))

	if _, ok := el.cachedProcFdFile(10, defaultPid); !ok {
		t.Fatalf("expected first cache entry to exist before refresh")
	}

	el.setProcFdCache(12, defaultPid, file.NewFdWithPid(12, defaultPid))

	if _, ok := el.cachedProcFdFile(10, defaultPid); !ok {
		t.Fatalf("expected recently used cache entry to be retained")
	}
	if _, ok := el.cachedProcFdFile(11, defaultPid); ok {
		t.Fatalf("expected least recently used cache entry to be evicted")
	}
	if _, ok := el.cachedProcFdFile(12, defaultPid); !ok {
		t.Fatalf("expected newest cache entry to be retained")
	}
	if got := len(el.procFdCacheAges); got != 2 {
		t.Fatalf("proc fd cache metadata size = %d, want 2", got)
	}
}
