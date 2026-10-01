package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// Task lz2: the drop-triggered staleness sweep (markAllStale) flags the cache
// entries that exist when the event loop applies it. A record reserved before
// the reported drop but consumed after the sweep (the loop works through a
// ring backlog) writes its name afterwards, non-stale, although the record the
// drop lost - say the same thread's next rename - never arrives. Writes from
// records no newer than the last drop stamp must therefore leave the entry
// stale, so its next use re-reads /proc once, like newtask seeds do
// (provisionalSeedNeedsRecheck).

const (
	backlogTid   = uint32(4400)
	dropStamp    = uint64(5000)
	beforeDrop   = dropStamp - 1000
	afterTheDrop = dropStamp + 1000
)

func backlogEventLoop(t *testing.T) *eventLoop {
	t.Helper()
	el, _ := newRecheckEventLoop(t, true, procfsComm)
	el.lastDropSeenBootNs.Store(dropStamp)
	return el
}

func cachedStale(t *testing.T, el *eventLoop, tid uint32, want string) bool {
	t.Helper()
	comm, ok, stale := el.commResolver.lookupCached(tid)
	if !ok || comm != want {
		t.Fatalf("cached comm of tid %d = %q (ok=%v), want %q", tid, comm, ok, want)
	}
	return stale
}

func TestBacklogRecordsOlderThanTheLastDropLeaveTheCommStale(t *testing.T) {
	writers := map[string]func(el *eventLoop, at uint64){
		"rename record": func(el *eventLoop, at uint64) {
			ev := &types.TaskRenameEvent{Time: at, Tid: backlogTid}
			copy(ev.Comm[:], "renamed")
			el.handleTaskRenameEvent(ev)
		},
		"open enter payload": func(el *eventLoop, at uint64) {
			ev := &types.OpenEvent{Time: at, Tid: backlogTid}
			copy(ev.Comm[:], "renamed")
			el.seedCommFromEnterPayload(ev)
		},
	}
	for name, write := range writers {
		t.Run(name+"/older than the drop", func(t *testing.T) {
			el := backlogEventLoop(t)
			write(el, beforeDrop)
			if !cachedStale(t, el, backlogTid, "renamed") {
				t.Fatal("a record reserved before the drop left a non-stale entry: the lost record can never be healed")
			}
		})
		t.Run(name+"/newer than the drop", func(t *testing.T) {
			el := backlogEventLoop(t)
			write(el, afterTheDrop)
			if cachedStale(t, el, backlogTid, "renamed") {
				t.Fatal("a record newer than the last drop was flagged stale: it costs a /proc read for nothing")
			}
		})
	}
}

func TestBacklogExecRecordOlderThanTheLastDropLeavesTheCommStale(t *testing.T) {
	for at, wantStale := range map[uint64]bool{beforeDrop: true, afterTheDrop: false} {
		el := backlogEventLoop(t)
		ev := &types.ProcessExecEvent{Time: at, Pid: backlogTid, Tid: backlogTid}
		copy(ev.Comm[:], "newprog")
		el.handleProcessExecEvent(ev, make(chan *event.Pair, 1))
		if got := cachedStale(t, el, backlogTid, "newprog"); got != wantStale {
			t.Fatalf("exec record at %d (last drop %d): stale = %v, want %v", at, dropStamp, got, wantStale)
		}
	}
}
