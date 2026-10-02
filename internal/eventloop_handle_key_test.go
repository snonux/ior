package internal

import (
	"syscall"
	"testing"

	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// TestHandleKeyDistinguishesTypeAndBytes: the key is the pair the kernel
// resolves, so a name filed under one handle must not name a handle that
// differs in its type, in one byte, or in its length (a prefix, or the same
// bytes with a zero more).
func TestHandleKeyDistinguishesTypeAndBytes(t *testing.T) {
	base := testHandleA
	others := map[string]testHandle{
		"same bytes, other type": {handleType: base.handleType + 1, bytes: base.bytes},
		"one byte differs":       {handleType: base.handleType, bytes: append([]byte{0x12}, base.bytes[1:]...)},
		"a prefix":               {handleType: base.handleType, bytes: base.bytes[:len(base.bytes)-1]},
		"a zero more":            {handleType: base.handleType, bytes: append(append([]byte{}, base.bytes...), 0)},
	}
	for name, other := range others {
		t.Run(name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			feed.nameToHandle("/data/a.txt", base)
			assertHandleRow(t, feed, feed.openByHandle(other, 70), 70, "")
			assertHandleRow(t, feed, feed.openByHandle(base, 71), 71, "/data/a.txt")
		})
	}
}

// TestHandleKeyOfRejectsWhatIdentifiesNoHandle covers every record that must
// be treated as "handle unknown": the statuses other than OK, an empty handle
// and a byte count beyond the field.
func TestHandleKeyOfRejectsWhatIdentifiesNoHandle(t *testing.T) {
	fHandle := testHandleA.fHandle()
	tests := []struct {
		name   string
		status uint32
		bytes  uint32
		want   bool
	}{
		{"ok", types.FILE_HANDLE_OK, 8, true},
		{"ok at the maximum size", types.FILE_HANDLE_OK, types.IOR_MAX_HANDLE_SZ, true},
		{"legacy record", types.FILE_HANDLE_NONE, 8, false},
		{"null pointer", types.FILE_HANDLE_NULL, 8, false},
		{"read failed", types.FILE_HANDLE_READ_FAILED, 8, false},
		{"too large", types.FILE_HANDLE_TOO_LARGE, 4096, false},
		{"unknown status", 99, 8, false},
		{"empty handle", types.FILE_HANDLE_OK, 0, false},
		{"byte count beyond the field", types.FILE_HANDLE_OK, types.IOR_MAX_HANDLE_SZ + 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := handleKeyOf(tc.status, tc.bytes, testHandleA.handleType, &fHandle)
			if ok != tc.want {
				t.Fatalf("handleKeyOf ok = %v, want %v", ok, tc.want)
			}
			if !ok && key != (handleKey{}) {
				t.Fatalf("a rejected handle returned the non-zero key %+v", key)
			}
		})
	}
}

// TestHandleKeyIgnoresBytesBehindTheHandle: only handle_bytes bytes are the
// handle. Whatever a producer left in the rest of the field must not make two
// records of one handle differ.
func TestHandleKeyIgnoresBytesBehindTheHandle(t *testing.T) {
	clean := testHandleA.fHandle()
	dirty := clean
	for i := len(testHandleA.bytes); i < len(dirty); i++ {
		dirty[i] = 0xee
	}
	size := uint32(len(testHandleA.bytes))
	cleanKey, _ := handleKeyOf(types.FILE_HANDLE_OK, size, testHandleA.handleType, &clean)
	dirtyKey, ok := handleKeyOf(types.FILE_HANDLE_OK, size, testHandleA.handleType, &dirty)
	if !ok || cleanKey != dirtyKey {
		t.Fatal("bytes behind the handle changed its key")
	}
	if cleanKey != testHandleA.key() {
		t.Fatalf("key = %+v, want %+v", cleanKey, testHandleA.key())
	}
}

// TestOpenWithAnUnreadableHandleFallsBackToProcfs: an enter record without a
// usable handle - an object that predates the capture, a failed read, an
// oversized or empty handle - names nothing, even when the bytes it carries
// happen to equal a known handle. The row then gets what procfs offers, which
// for the absent fixture task is no name.
func TestOpenWithAnUnreadableHandleFallsBackToProcfs(t *testing.T) {
	tests := map[string]func(ev *types.OpenByHandleAtEvent){
		"legacy record": func(ev *types.OpenByHandleAtEvent) { ev.HandleStatus = types.FILE_HANDLE_NONE },
		"read failed":   func(ev *types.OpenByHandleAtEvent) { ev.HandleStatus = types.FILE_HANDLE_READ_FAILED },
		"null pointer":  func(ev *types.OpenByHandleAtEvent) { ev.HandleStatus = types.FILE_HANDLE_NULL },
		"too large": func(ev *types.OpenByHandleAtEvent) {
			ev.HandleStatus, ev.HandleBytes = types.FILE_HANDLE_TOO_LARGE, types.IOR_MAX_HANDLE_SZ+1
		},
		"empty handle": func(ev *types.OpenByHandleAtEvent) { ev.HandleBytes = 0 },
	}
	for name, spoil := range tests {
		t.Run(name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			feed.nameToHandle("/data/a.txt", testHandleA)
			ev, _ := makeEnterOpenByHandleEvent(t, feed.time, feed.pid, feed.tid, syscall.O_RDONLY, testHandleA)
			spoil(&ev)
			assertHandleRow(t, feed, feed.finishOpen(eventBytes(t, &ev), 70), 70, "")
		})
	}
}

// TestLegacyOpenByHandleAtRecordStillMakesARow: the 32-byte record of an
// IOR_BPF_OBJECT that predates the handle decodes without one and is named
// like any unknown handle, with the call's flags.
func TestLegacyOpenByHandleAtRecordStillMakesARow(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)
	_, current := makeEnterOpenByHandleEvent(t, feed.time, feed.pid, feed.tid, syscall.O_RDWR, testHandleA)
	legacy := append([]byte{}, current[:32]...)

	ep := feed.finishOpen(legacy, 70)
	assertHandleRow(t, feed, ep, 70, "")
	if got := ep.File.(*file.FdFile).Flags(); got != file.Flags(syscall.O_RDWR) {
		t.Fatalf("row flags = %v, want the call's O_RDWR", got)
	}
}

func TestHandleTrackerEvictsLeastRecentlyUsed(t *testing.T) {
	tracker := newHandleTracker()
	tracker.maxCacheSize = 2
	keyA, keyB, keyC := testHandleA.key(), testHandleB.key(), defaultTestHandle.key()

	tracker.store(keyA, "/a")
	tracker.store(keyB, "/b")
	if _, ok := tracker.lookup(keyA); !ok {
		t.Fatal("stored handle is not known")
	}
	tracker.store(keyC, "/c")

	if _, ok := tracker.names[keyB]; ok {
		t.Fatal("the least recently used handle survived the cap")
	}
	if name, ok := tracker.lookup(keyA); !ok || name != "/a" {
		t.Fatalf("a handle used after the evicted one was dropped: (%q, %v)", name, ok)
	}
	if name, ok := tracker.lookup(keyC); !ok || name != "/c" {
		t.Fatalf("the newest handle was dropped: (%q, %v)", name, ok)
	}
	if got := len(tracker.nameAges); got != len(tracker.names) {
		t.Fatalf("age map holds %d entries for %d names", got, len(tracker.names))
	}
}

// TestHandleTrackerEmptyNameSupersedes: a handle returned again by a call ior
// has no name for must not keep its old name.
func TestHandleTrackerEmptyNameSupersedes(t *testing.T) {
	tracker := newHandleTracker()
	tracker.store(testHandleA.key(), "/a")
	tracker.store(testHandleB.key(), "/b")
	tracker.store(testHandleA.key(), "")

	if name, ok := tracker.lookup(testHandleA.key()); ok {
		t.Fatalf("handle kept the superseded name %q", name)
	}
	if name, ok := tracker.lookup(testHandleB.key()); !ok || name != "/b" {
		t.Fatalf("another handle lost its name: (%q, %v)", name, ok)
	}
	if len(tracker.nameAges) != 1 {
		t.Fatalf("age map holds %d entries, want 1", len(tracker.nameAges))
	}
}

// TestHandleTrackerClaimNeedsTheParkingCallsTime pins the pairing of the
// control record with its exit record: only the exit that carries the
// record's time claims the handle, any exit drops the parked entry, and a
// tid's entries are its own.
func TestHandleTrackerClaimNeedsTheParkingCallsTime(t *testing.T) {
	tracker := newHandleTracker()
	const tid, sibling = 7, 8

	tracker.park(tid, testHandleA.key(), 100)
	if _, ok := tracker.claim(sibling, 100); ok {
		t.Fatal("a sibling thread claimed the handle")
	}
	if key, ok := tracker.claim(tid, 100); !ok || key != testHandleA.key() {
		t.Fatalf("claim = (%+v, %v), want the parked handle", key, ok)
	}
	if _, ok := tracker.claim(tid, 100); ok {
		t.Fatal("a handle was claimed twice")
	}

	tracker.park(tid, testHandleA.key(), 100)
	if _, ok := tracker.claim(tid, 200); ok {
		t.Fatal("an exit with another time claimed the handle")
	}
	if len(tracker.taken) != 0 {
		t.Fatal("a mismatching exit left the handle parked")
	}
}

// TestHandleTrackerParkedHandlesAreBounded: parked entries normally live for
// a few records, so leftovers of lost exit records are dropped wholesale at
// the cap instead of being aged.
func TestHandleTrackerParkedHandlesAreBounded(t *testing.T) {
	tracker := newHandleTracker()
	tracker.maxCacheSize = 3
	for tid := uint32(1); tid <= 4; tid++ {
		tracker.park(tid, testHandleA.key(), uint64(tid))
	}
	if got := len(tracker.taken); got != 1 {
		t.Fatalf("%d handles parked after overflowing a cap of 3, want only the newest", got)
	}
	if _, ok := tracker.claim(4, 4); !ok {
		t.Fatal("the handle parked last was dropped")
	}
}
