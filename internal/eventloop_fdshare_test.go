package internal

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Task hr2: two processes that clone(CLONE_FILES) share one descriptor table,
// but the tracker kept one table per tgid, so whatever the child closed, opened
// or dup2()ed left the creator's entries (and the child's own) describing a
// table that no longer existed: a read of fd 3 was labelled /etc/hostname after
// the kernel had pointed it at /etc/os-release. These tests drive the same
// records and syscalls the kernel produces through the event loop, and pin the
// table-id indirection (eventloop_fdshare.go) that models the sharing.

const (
	shareCreator = forkParentPid
	shareChild   = forkChildPid
	shareHost    = "/etc/hostname"
	shareOsRel   = "/etc/os-release"
)

// makeScopedForkRecord is makeForkRecord with the record's scope_flags word.
func makeScopedForkRecord(t *testing.T, creator, pid, tid uint32, flags uint64, scopeFlags uint32) []byte {
	t.Helper()
	ev := types.TaskNewtaskEvent{
		EventType:  types.TASK_NEWTASK_EVENT,
		Time:       forkStart - 10,
		Pid:        pid,
		Tid:        tid,
		CloneFlags: flags,
		CreatorPid: creator,
		ScopeFlags: scopeFlags,
	}
	copy(ev.Comm[:], "sharer")
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("TaskNewtaskEvent.Bytes() error = %v", err)
	}
	return raw
}

// openAs registers fd as path in pid's table through a real openat pair.
func openAs(t *testing.T, el *eventLoop, pid uint32, path string, fd int64) {
	t.Helper()
	if ep := feedOpenPairForPid(t, el, path, pid, pid, fd); ep != nil {
		ep.Recycle()
	}
}

// closeAs feeds a successful close(fd) of pid.
func closeAs(t *testing.T, el *eventLoop, pid uint32, fd int32) {
	t.Helper()
	_, enterRaw := makeEnterFdEvent(t, forkStart, pid, pid, fd, types.SYS_ENTER_CLOSE)
	_, exitRaw := makeExitCloseEvent(t, forkStart+100, pid, pid, 0)
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		ep.Recycle()
	}
}

// closeRangeAs feeds a successful close_range(first, last, flags) of the
// process pid, called by its leader thread.
func closeRangeAs(t *testing.T, el *eventLoop, pid uint32, first, last int32, flags uint64) {
	t.Helper()
	closeRangeAsTid(t, el, pid, pid, first, last, flags)
}

// closeRangeAsTid feeds the same call made by thread tid of process pid.
func closeRangeAsTid(t *testing.T, el *eventLoop, pid, tid uint32, first, last int32, flags uint64) {
	t.Helper()
	_, enterRaw := makeEnterTwoFdEvent(t, forkStart, pid, tid, first, last, flags, types.SYS_ENTER_CLOSE_RANGE)
	_, exitRaw := makeExitRetEvent(t, forkStart+100, pid, tid, types.SYS_EXIT_CLOSE_RANGE, 0)
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		ep.Recycle()
	}
}

// readName is what a read(fd) row of pid would print as its file.
func readName(t *testing.T, el *eventLoop, pid uint32, fd int32) string {
	t.Helper()
	return feedReadOn(t, el, pid, pid, fd).Name()
}

// assertFdShareInvariants checks the bookkeeping that every operation must leave
// exact: the per-pid index mirrors the maps, the alias map and its inverse
// agree, no entry is keyed under a pid that only aliases another's table, and a
// table id is never itself an alias. For the blind set (markBlind): a blind id
// names a table, never an alias (markBlind resolves through tableID and
// handOverTable moves the mark with the table), and it tracks nothing: neither
// fd-table nor procfs-cache entries are keyed under it, which is what makes
// every lookup fall through to procfs instead of answering a possibly wrong name.
func assertFdShareInvariants(t *testing.T, tr *fdTracker) {
	t.Helper()
	for key := range tr.files {
		pid, _ := fdKeyParts(key)
		if keys := tr.pidIndex[pid]; keys == nil || !hasKey(keys.files, key) {
			t.Errorf("fd-table key %#x missing from the pid index", key)
		}
		if _, alias := tr.share.tableOf[pid]; alias {
			t.Errorf("entry keyed under pid %d, which only aliases table %d", pid, tr.share.tableOf[pid])
		}
	}
	for key := range tr.procFdCache {
		pid, _ := fdKeyParts(key)
		if keys := tr.pidIndex[pid]; keys == nil || !hasKey(keys.cache, key) {
			t.Errorf("cache key %#x missing from the pid index", key)
		}
	}
	for pid, keys := range tr.pidIndex {
		if len(keys.files) == 0 && len(keys.cache) == 0 {
			t.Errorf("pid %d kept an empty index entry", pid)
		}
		for key := range keys.files {
			if _, ok := tr.files[key]; !ok {
				t.Errorf("index of pid %d names a file key %#x that is gone", pid, key)
			}
		}
		for key := range keys.cache {
			if _, ok := tr.procFdCache[key]; !ok {
				t.Errorf("index of pid %d names a cache key %#x that is gone", pid, key)
			}
		}
	}
	for pid, id := range tr.share.tableOf {
		if !hasPid(tr.share.sharers[id], pid) {
			t.Errorf("pid %d aliases table %d but is not in its sharer set", pid, id)
		}
		if _, chained := tr.share.tableOf[id]; chained {
			t.Errorf("table id %d of pid %d is itself an alias", id, pid)
		}
	}
	assertBlindInvariants(t, tr)
	for id, members := range tr.share.sharers {
		if len(members) == 0 {
			t.Errorf("table %d kept an empty sharer set", id)
		}
		for m := range members {
			if tr.share.tableOf[m] != id {
				t.Errorf("sharer %d of table %d maps to %d", m, id, tr.share.tableOf[m])
			}
		}
	}
}

// assertBlindInvariants is the blind-set part of assertFdShareInvariants.
func assertBlindInvariants(t *testing.T, tr *fdTracker) {
	t.Helper()
	for id := range tr.share.blind {
		if owner, alias := tr.share.tableOf[id]; alias {
			t.Errorf("blind id %d only aliases table %d: the mark must sit on the table id", id, owner)
		}
		if keys := tr.pidIndex[id]; keys != nil {
			t.Errorf("blind table %d tracks %d fd entries and %d cache entries, want none",
				id, len(keys.files), len(keys.cache))
		}
	}
}

// sharesTable reports whether pid's table has another tgid using it. Only the
// tests ask; production code never needs to know.
func (t *fdTracker) sharesTable(pid uint32) bool {
	if _, ok := t.share.tableOf[pid]; ok {
		return true
	}
	return len(t.share.sharers[pid]) > 0
}

func hasKey(set map[uint64]struct{}, key uint64) bool { _, ok := set[key]; return ok }
func hasPid(set map[uint32]struct{}, pid uint32) bool { _, ok := set[pid]; return ok }

// TestCloneFilesChildReplacesADescriptorTheCreatorReads is the reproduction
// (clonefiles.c): the creator reads fd 3 (/etc/hostname), a CLONE_FILES child
// closes fd 3 and opens another file on the number, and the creator's next read
// of fd 3 must name the new file - the kernel says so, the pre-hr2 tracker kept
// answering /etc/hostname.
func TestCloneFilesChildReplacesADescriptorTheCreatorReads(t *testing.T) {
	el := newTaskEventLoop(t, "")
	openAs(t, el, shareCreator, shareHost, 3)
	if got := readName(t, el, shareCreator, 3); got != shareHost {
		t.Fatalf("setup: creator fd 3 = %q, want %q", got, shareHost)
	}

	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)
	closeAs(t, el, shareChild, 3)
	openAs(t, el, shareChild, shareOsRel, 3)

	if got := readName(t, el, shareCreator, 3); got != shareOsRel {
		t.Errorf("creator fd 3 = %q after the CLONE_FILES child replaced it, want %q", got, shareOsRel)
	}
	if got := readName(t, el, shareChild, 3); got != shareOsRel {
		t.Errorf("child fd 3 = %q, want %q", got, shareOsRel)
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestForkedChildReplacingADescriptorLeavesTheCreatorAlone is the negative
// control of the test above: the very same child syscalls after a plain fork
// must not reach the creator (each has its own table). If sharing were applied
// to every child, this would fail.
func TestForkedChildReplacingADescriptorLeavesTheCreatorAlone(t *testing.T) {
	el := newTaskEventLoop(t, "")
	openAs(t, el, shareCreator, shareHost, 3)

	feedForkRecord(t, el, shareCreator, shareChild, shareChild, forkSigchld)
	closeAs(t, el, shareChild, 3)
	openAs(t, el, shareChild, shareOsRel, 3)

	if got := readName(t, el, shareCreator, 3); got != shareHost {
		t.Errorf("creator fd 3 = %q after a forked child replaced its own copy, want %q", got, shareHost)
	}
	if got := readName(t, el, shareChild, 3); got != shareOsRel {
		t.Errorf("child fd 3 = %q, want %q", got, shareOsRel)
	}
}

// TestCloneFilesSharingWorksBothWays: what the creator opens after the clone
// is the child's too (and the creator's close ends it for the child).
func TestCloneFilesSharingWorksBothWays(t *testing.T) {
	el := newTaskEventLoop(t, "")
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

	openAs(t, el, shareCreator, shareHost, 7)
	if got := readName(t, el, shareChild, 7); got != shareHost {
		t.Errorf("child fd 7 = %q, want the creator's new open %q", got, shareHost)
	}
	closeAs(t, el, shareCreator, 7)
	if _, ok := el.fdState().get(7, shareChild); ok {
		t.Error("the creator's close(7) did not reach the shared table")
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestCloneFilesChildExitKeepsTheCreatorsTable: a sharer leaving (its group-dead
// exit record) must not take the table with it.
func TestCloneFilesChildExitKeepsTheCreatorsTable(t *testing.T) {
	el := newTaskEventLoop(t, "")
	openAs(t, el, shareCreator, shareHost, 3)
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

	el.processRawEvent(makeProcessExitEvent(t, forkStart, shareChild, shareChild), make(chan *event.Pair, 1))

	if got := readName(t, el, shareCreator, 3); got != shareHost {
		t.Errorf("creator fd 3 = %q after the sharer exited, want %q", got, shareHost)
	}
	if el.fdState().sharesTable(shareCreator) {
		t.Error("the creator still counts a sharer after its exit")
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestCloneFilesHolderExitHandsTheTableToTheSharer: the creator exits first
// (the usual order of a launcher that hands a pool over) and the child, which
// keeps running, must still find the descriptors - and the creator's tgid, which
// the kernel will reuse, must not: a new process of that number has no table.
func TestCloneFilesHolderExitHandsTheTableToTheSharer(t *testing.T) {
	el := newTaskEventLoop(t, "")
	openAs(t, el, shareCreator, shareHost, 3)
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)
	third := uint32(forkChildPid + 1)
	feedForkRecord(t, el, shareCreator, third, third, cloneFlagFiles|forkSigchld)

	el.processRawEvent(makeProcessExitEvent(t, forkStart, shareCreator, shareCreator), make(chan *event.Pair, 1))

	for _, pid := range []uint32{shareChild, third} {
		if got := readName(t, el, pid, 3); got != shareHost {
			t.Errorf("sharer %d fd 3 = %q after the holder exited, want %q", pid, got, shareHost)
		}
	}
	// Both sharers still share one table with each other...
	closeAs(t, el, shareChild, 3)
	if _, ok := el.fdState().get(3, third); ok {
		t.Error("after the hand-over the two remaining sharers no longer share one table")
	}
	// ... and the exited holder's number names no table.
	openAs(t, el, shareChild, shareOsRel, 4)
	if _, ok := el.fdState().get(4, shareCreator); ok {
		t.Error("the exited holder's tgid still resolves into the table it handed over")
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestCloneFilesChildExecGetsAPrivateCopy: execve unshares the table before the
// close-on-exec descriptors go (unshare_files in begin_new_exec), so the exec'ing
// sharer loses them but the creator keeps every one.
func TestCloneFilesChildExecGetsAPrivateCopy(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.fdState().set(3, shareCreator, file.NewFd(3, "/keep", syscall.O_RDONLY))
	el.fdState().set(4, shareCreator, file.NewFd(4, "/cloexec", syscall.O_RDONLY|syscall.O_CLOEXEC))
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

	el.processRawEvent(makeProcessExecEvent(t, forkStart, shareChild, shareChild, "newprog"), make(chan *event.Pair, 1))

	if _, ok := el.fdState().get(3, shareChild); !ok {
		t.Error("the exec'd child lost a descriptor that survives exec")
	}
	if _, ok := el.fdState().get(4, shareChild); ok {
		t.Error("the exec'd child kept a close-on-exec descriptor")
	}
	if _, ok := el.fdState().get(4, shareCreator); !ok {
		t.Error("the child's exec closed the creator's close-on-exec descriptor")
	}
	// The table is no longer shared: a close by the child stays its own.
	closeAs(t, el, shareChild, 3)
	if _, ok := el.fdState().get(3, shareCreator); !ok {
		t.Error("after the exec the child's close(3) still reached the creator")
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestCloneFilesHolderExecKeepsTheTableForItsSharers is the exec case seen from
// the holder: the creator execs, the child keeps the original table.
func TestCloneFilesHolderExecKeepsTheTableForItsSharers(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.fdState().set(4, shareCreator, file.NewFd(4, "/cloexec", syscall.O_RDONLY|syscall.O_CLOEXEC))
	el.fdState().set(3, shareCreator, file.NewFd(3, "/keep", syscall.O_RDONLY))
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

	el.processRawEvent(makeProcessExecEvent(t, forkStart, shareCreator, shareCreator, "newprog"), make(chan *event.Pair, 1))

	if _, ok := el.fdState().get(4, shareChild); !ok {
		t.Error("the creator's exec closed the close-on-exec descriptor of the table it shares with the child")
	}
	if _, ok := el.fdState().get(4, shareCreator); ok {
		t.Error("the creator kept a close-on-exec descriptor across its exec")
	}
	if _, ok := el.fdState().get(3, shareCreator); !ok {
		t.Error("the creator lost a descriptor that survives exec")
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestCloseRangeUnshareDetachesASharer: close_range(CLOSE_RANGE_UNSHARE) closes
// in a private copy, so the creator keeps every descriptor; without the flag the
// same call closes them for both (the negative control).
func TestCloseRangeUnshareDetachesASharer(t *testing.T) {
	for _, tc := range []struct {
		name         string
		flags        uint64
		creatorKeeps bool
	}{
		{"with CLOSE_RANGE_UNSHARE", closeRangeUnshare, true},
		{"without it", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, "")
			el.fdState().set(3, shareCreator, file.NewFd(3, shareHost, syscall.O_RDONLY))
			el.fdState().set(4, shareCreator, file.NewFd(4, shareOsRel, syscall.O_RDONLY))
			feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

			closeRangeAs(t, el, shareChild, 3, -1, tc.flags)

			for _, fd := range []int32{3, 4} {
				if _, ok := el.fdState().get(fd, shareChild); ok {
					t.Errorf("the caller still tracks fd %d after closing the range", fd)
				}
				if _, ok := el.fdState().get(fd, shareCreator); ok != tc.creatorKeeps {
					t.Errorf("creator tracks fd %d = %v, want %v", fd, ok, tc.creatorKeeps)
				}
			}
			assertFdShareInvariants(t, el.fdState())
		})
	}
}

// TestCloseRangeUnshareCloexecMarksOnlyThePrivateCopy: UNSHARE|CLOEXEC marks
// the descriptors close-on-exec in the caller's copy; the creator's stay clear.
func TestCloseRangeUnshareCloexecMarksOnlyThePrivateCopy(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.fdState().set(3, shareCreator, file.NewFd(3, shareHost, syscall.O_RDONLY))
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

	closeRangeAs(t, el, shareChild, 3, 3, closeRangeUnshare|closeRangeCloexec)

	child, _ := el.fdState().get(3, shareChild)
	creator, _ := el.fdState().get(3, shareCreator)
	if set, known := child.(*file.FdFile).CloseOnExec(); !known || !set {
		t.Error("the caller's copy was not marked close-on-exec")
	}
	if set, known := creator.(*file.FdFile).CloseOnExec(); !known || set {
		t.Error("the creator's descriptor was marked close-on-exec by the sharer's unshared call")
	}
}

// TestForkFromASharerCopiesTheSharedTable: a plain fork by a CLONE_FILES child
// copies the table it uses (the creator's), not an empty slot keyed by its tgid.
func TestForkFromASharerCopiesTheSharedTable(t *testing.T) {
	el := newTaskEventLoop(t, "")
	openAs(t, el, shareCreator, shareHost, 3)
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)
	grandchild := uint32(forkChildPid + 50)

	feedForkRecord(t, el, shareChild, grandchild, grandchild, forkSigchld)

	if got := readName(t, el, grandchild, 3); got != shareHost {
		t.Errorf("fork of a sharer: grandchild fd 3 = %q, want %q", got, shareHost)
	}
	closeAs(t, el, grandchild, 3)
	if _, ok := el.fdState().get(3, shareCreator); !ok {
		t.Error("the forked grandchild's close(3) reached the table its parent shares")
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestRecycledPidThatHeldASharedTableKeepsItForItsSharers: a lost exit record
// leaves a stale holder whose number is handed out again; the new process must
// start clean without pulling the table away from the processes still sharing it.
func TestRecycledPidThatHeldASharedTableKeepsItForItsSharers(t *testing.T) {
	el := newTaskEventLoop(t, "")
	openAs(t, el, shareCreator, shareHost, 3)
	feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

	// The creator's number comes back as a brand-new process (its exit was lost).
	feedForkRecord(t, el, 1, shareCreator, shareCreator, forkSigchld)

	if got := readName(t, el, shareChild, 3); got != shareHost {
		t.Errorf("surviving sharer fd 3 = %q, want %q", got, shareHost)
	}
	if _, ok := el.fdState().get(3, shareCreator); ok {
		t.Error("the recycled pid inherited the previous holder's table")
	}
	assertFdShareInvariants(t, el.fdState())
}

// TestCloseRangeUnshareByAWorkerThreadLeavesTheTableAlone: a thread that is not
// the group leader privatises only its own table, so the tgid's table, which the
// tracker keys by and which the other threads and a CLONE_FILES process still
// use, must be neither detached nor closed. The negative control is the same call
// by the leader, which does detach (and closes the range in its private copy).
func TestCloseRangeUnshareByAWorkerThreadLeavesTheTableAlone(t *testing.T) {
	const worker = shareChild + 1
	for _, tc := range []struct {
		name       string
		tid        uint32
		wantShared bool // the child is still aliased to the creator's table
		wantKept   bool // the creator still tracks fd 3 afterwards
	}{
		{"worker thread", worker, true, true},
		{"leader (negative control)", shareChild, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, "")
			openAs(t, el, shareCreator, shareHost, 3)
			feedForkRecord(t, el, shareCreator, shareChild, shareChild, cloneFlagFiles|forkSigchld)

			closeRangeAsTid(t, el, shareChild, tc.tid, 3, -1, closeRangeUnshare)

			if got := el.fdState().sharesTable(shareChild); got != tc.wantShared {
				t.Errorf("child still shares the table = %v, want %v", got, tc.wantShared)
			}
			_, ok := el.fdState().get(3, shareCreator)
			if ok != tc.wantKept {
				t.Errorf("creator tracks fd 3 = %v, want %v", ok, tc.wantKept)
			}
			if tc.wantShared {
				// The thread's range was applied to its private table, not ours.
				if _, ok := el.fdState().get(3, shareChild); !ok {
					t.Error("the shared table lost fd 3 to a worker thread's private close_range")
				}
			}
			assertFdShareInvariants(t, el.fdState())
		})
	}
}

// TestCloseRangeUnshareDoesNotUnblindATable is the reviewed failure: -pid P, P
// runs an out-of-scope clone(CLONE_FILES) child, and then a thread of P calls
// close_range(CLOSE_RANGE_UNSHARE). The table must stay blind (answered from
// procfs) after the worker's call, and after the leader's too: a leader cannot be
// told to be alone, and the invisible child may still share the table with a
// sibling thread. Only an exec un-blinds (detachShared, exact).
func TestCloseRangeUnshareDoesNotUnblindATable(t *testing.T) {
	const worker = shareCreator + 1
	for _, tid := range []uint32{worker, shareCreator} {
		el := newTaskEventLoop(t, "")
		el.processRawEvent(makeScopedForkRecord(t, shareCreator, shareChild, shareChild,
			cloneFlagFiles|forkSigchld, types.TaskNewtaskChildOutOfScope), make(chan *event.Pair, 1))
		if !el.fdState().isBlind(shareCreator) {
			t.Fatal("the out-of-scope record did not blind the creator's table")
		}

		closeRangeAsTid(t, el, shareCreator, tid, 3, -1, closeRangeUnshare)

		if !el.fdState().isBlind(shareCreator) {
			t.Errorf("close_range(UNSHARE) by tid %d un-blinded a table an invisible process still shares", tid)
		}
		assertFdShareInvariants(t, el.fdState())
	}

	// Contrast: an exec leaves nobody else on the table, so it does un-blind.
	el := newTaskEventLoop(t, "")
	el.processRawEvent(makeScopedForkRecord(t, shareCreator, shareChild, shareChild,
		cloneFlagFiles|forkSigchld, types.TaskNewtaskChildOutOfScope), make(chan *event.Pair, 1))
	el.fdState().detachShared(shareCreator)
	if el.fdState().isBlind(shareCreator) {
		t.Error("an exec did not un-blind the table")
	}
}

// TestCloseRangeUnshareByABlindSharerStaysBlind: an in-scope sharer of a blind
// table that unshares leaves the group but takes the blind mark along (it may
// have sibling threads that still share the table with the invisible process).
func TestCloseRangeUnshareByABlindSharerStaysBlind(t *testing.T) {
	el := newTaskEventLoop(t, "")
	tr := el.fdState()
	tr.shareTable(shareChild, shareCreator)
	tr.markBlind(shareCreator)

	closeRangeAs(t, el, shareChild, 3, -1, closeRangeUnshare)

	if tr.sharesTable(shareChild) || !tr.isBlind(shareChild) || !tr.isBlind(shareCreator) {
		t.Errorf("shares=%v blind(child)=%v blind(creator)=%v, want false true true",
			tr.sharesTable(shareChild), tr.isBlind(shareChild), tr.isBlind(shareCreator))
	}
	assertFdShareInvariants(t, tr)
}

// TestCloseRangeUnshareByTheLeaderOfABlindTableWithSharers: a blind table whose
// leader (the holder the entries were keyed by) has an in-scope sharer, and the
// leader unshares via close_range(UNSHARE): unshareFiles hands the table over to
// the sharer (handOverTable moves the blind mark to the heir) and then marks the
// leader blind again (markBlind), because the leader's siblings may still share
// the old table with the invisible process. Both ends must stay blind and empty:
// the leader with a private table of its own, the sharer holding the old one; no
// entry may appear under either id, so every lookup of either falls to procfs
// instead of answering a name the invisible task may have changed.
func TestCloseRangeUnshareByTheLeaderOfABlindTableWithSharers(t *testing.T) {
	el := newTaskEventLoop(t, "")
	tr := el.fdState()
	openAs(t, el, shareCreator, shareHost, 3) // tracked before the table goes blind
	tr.shareTable(shareChild, shareCreator)
	tr.markBlind(shareCreator)
	if _, ok := tr.get(3, shareCreator); ok {
		t.Fatal("markBlind kept a tracked entry")
	}

	closeRangeAs(t, el, shareCreator, 3, -1, closeRangeUnshare)

	if tr.sharesTable(shareCreator) || tr.sharesTable(shareChild) {
		t.Error("the leader and the sharer still share a table after the unshare")
	}
	if !tr.isBlind(shareCreator) || !tr.isBlind(shareChild) {
		t.Errorf("blind(leader)=%v blind(sharer)=%v, want both true", tr.isBlind(shareCreator), tr.isBlind(shareChild))
	}
	if len(tr.share.blind) != 2 {
		t.Errorf("blind set %v, want exactly the leader's private table and the sharer's", tr.share.blind)
	}
	// New opens on either side must not be tracked (they would be named from a
	// table the invisible process also writes), so procfs keeps answering.
	openAs(t, el, shareCreator, shareOsRel, 5)
	openAs(t, el, shareChild, shareOsRel, 6)
	for _, probe := range []struct {
		pid uint32
		fd  int32
	}{{shareCreator, 3}, {shareCreator, 5}, {shareChild, 3}, {shareChild, 6}} {
		if _, ok := tr.get(probe.fd, probe.pid); ok {
			t.Errorf("pid %d fd %d is tracked, a blind table must answer from procfs", probe.pid, probe.fd)
		}
	}
	assertFdShareInvariants(t, tr)
}

// TestNewCloneFilesChildDropsWhatAStaleNumberAliased pins the deletePid call in
// shareTable. The tgid of a dead task whose exit record was lost comes back as
// the child of a new CLONE_FILES record; if the stale state were kept, the
// sharer bookkeeping would still list it under its old table, and when that
// table's holder exited handOverTable would re-point the new child back at the
// old table (stale holder: the same, with the dead task's entries in the way).
func TestNewCloneFilesChildDropsWhatAStaleNumberAliased(t *testing.T) {
	const (
		oldHolder, otherSharer, stale = 10, 11, 12
		newCreator                    = 20
	)
	for _, tc := range []struct {
		name  string
		stale uint32 // the reused tgid
	}{
		{"stale sharer of another table", stale},
		{"stale holder of another table", oldHolder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, "")
			tr := el.fdState()
			tr.set(3, oldHolder, file.NewFd(3, shareHost, syscall.O_RDONLY))
			tr.shareTable(otherSharer, oldHolder)
			tr.shareTable(stale, oldHolder)
			openAs(t, el, newCreator, shareOsRel, 3)

			// The reused tgid is now a CLONE_FILES child of the new creator.
			feedForkRecord(t, el, newCreator, tc.stale, tc.stale, cloneFlagFiles|forkSigchld)
			assertFdShareInvariants(t, tr)

			if tc.stale != oldHolder {
				tr.deletePid(oldHolder) // the old table's holder exits later
				assertFdShareInvariants(t, tr)
			}
			if got := readName(t, el, tc.stale, 3); got != shareOsRel {
				t.Errorf("the new child's fd 3 = %q, want the new creator's %q", got, shareOsRel)
			}
			if got := readName(t, el, otherSharer, 3); got != shareHost {
				t.Errorf("the old table's remaining sharer lost its table: fd 3 = %q, want %q", got, shareHost)
			}
		})
	}
}

// TestOutOfScopeCloneFilesChildBlindsTheCreatorsTable is the -pid case
// (clonefiles.c run under -pid <parent>): the child's syscalls never reach the
// trace, so the tracker cannot follow what it does to the shared table. The
// record that says so must make the creator's reads resolve through procfs. The
// creator is the test process, so procfs really answers: a real descriptor is
// repointed by a dup3 the trace never sees, and the name must follow it.
func TestOutOfScopeCloneFilesChildBlindsTheCreatorsTable(t *testing.T) {
	dir := t.TempDir()
	pathA, pathB := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	fdA, fdB := realFile(t, pathA), realFile(t, pathB)
	self := uint32(os.Getpid())

	for _, tc := range []struct {
		name      string
		scope     uint32
		wantAfter string
	}{
		{"out-of-scope record: procfs answers", types.TaskNewtaskChildOutOfScope, pathB},
		// Negative control: without the record the tracker keeps answering with
		// the name it saw, which is the bug (and proves the dup3 below works).
		{"no record: the stale traced name", 0, pathA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, "")
			const probeFd = 200
			if err := unix.Dup3(fdA, probeFd, 0); err != nil {
				t.Fatalf("dup3 setup: %v", err)
			}
			t.Cleanup(func() { _ = unix.Close(probeFd) })
			openAs(t, el, self, pathA, probeFd)

			if tc.scope != 0 {
				el.processRawEvent(makeScopedForkRecord(t, self, forkChildPid, forkChildPid,
					cloneFlagFiles|forkSigchld, tc.scope), make(chan *event.Pair, 1))
			}
			// What the invisible child does: repoint the shared number.
			if err := unix.Dup3(fdB, probeFd, 0); err != nil {
				t.Fatalf("dup3 (the invisible child's write): %v", err)
			}
			if got := readName(t, el, self, probeFd); got != tc.wantAfter {
				t.Errorf("read of the shared descriptor named %q, want %q", got, tc.wantAfter)
			}
		})
	}
}

// realFile opens path (creating it) and returns a descriptor closed at cleanup.
func realFile(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// TestBlindTableIsNotTrackedAgain: after the record, neither traced opens nor
// procfs answers may be stored for the creator (they would go stale at once),
// other processes keep tracking normally, and an exec of the creator - which
// unshares the table, so no invisible writer is left - tracks again.
func TestBlindTableIsNotTrackedAgain(t *testing.T) {
	el := newTaskEventLoop(t, "")
	openAs(t, el, shareCreator, shareHost, 3)
	openAs(t, el, 9000, shareHost, 3)
	el.processRawEvent(makeScopedForkRecord(t, shareCreator, shareChild, shareChild,
		cloneFlagFiles|forkSigchld, types.TaskNewtaskChildOutOfScope), make(chan *event.Pair, 1))
	tr := el.fdState()

	if _, ok := tr.get(3, shareCreator); ok {
		t.Error("the blinded creator kept a tracked entry")
	}
	openAs(t, el, shareCreator, shareOsRel, 5)
	tr.setProcFdCache(6, shareCreator, file.NewFd(6, "/procfs/answer", syscall.O_RDONLY))
	if _, ok := tr.get(5, shareCreator); ok {
		t.Error("an open of the blinded creator was tracked")
	}
	if _, ok := tr.cachedProcFdFile(6, shareCreator); ok {
		t.Error("a procfs answer for the blinded creator was cached")
	}
	if _, ok := tr.get(3, 9000); !ok {
		t.Error("blinding one process dropped another's entries")
	}
	if _, ok := tr.get(3, shareChild); ok {
		t.Error("the out-of-scope child was given a table")
	}

	el.processRawEvent(makeProcessExecEvent(t, forkStart, shareCreator, shareCreator, "newprog"), make(chan *event.Pair, 1))
	openAs(t, el, shareCreator, shareOsRel, 5)
	if _, ok := tr.get(5, shareCreator); !ok {
		t.Error("after the creator's exec (private table) opens are tracked again")
	}
	assertFdShareInvariants(t, tr)
}

// TestOutOfScopeRecordTouchesNothingOfTheChild: the child is not a task of this
// trace, so the record seeds no comm for it and leaves its per-tid state alone;
// only the creator's table is affected. A record without the flag still seeds
// the comm (the regression guard for the ordinary path).
func TestOutOfScopeRecordTouchesNothingOfTheChild(t *testing.T) {
	for _, tc := range []struct {
		name     string
		scope    uint32
		wantComm bool
	}{
		{"child out of scope", types.TaskNewtaskChildOutOfScope, false},
		{"child in scope", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, "")
			el.processRawEvent(makeScopedForkRecord(t, shareCreator, shareChild, shareChild,
				cloneFlagFiles|forkSigchld, tc.scope), make(chan *event.Pair, 1))
			if _, ok := el.commResolver.cached(shareChild); ok != tc.wantComm {
				t.Errorf("comm cached for the child = %v, want %v", ok, tc.wantComm)
			}
		})
	}
}

// TestOutOfScopeRecordWithoutACreatorIsIgnored: a flagged record that names no
// creator has no table to blind (and must not blind pid 0's).
func TestOutOfScopeRecordWithoutACreatorIsIgnored(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.processRawEvent(makeScopedForkRecord(t, 0, shareChild, shareChild,
		cloneFlagFiles|forkSigchld, types.TaskNewtaskChildOutOfScope), make(chan *event.Pair, 1))
	if len(el.fdState().share.blind) != 0 {
		t.Fatalf("blind set = %v, want empty", el.fdState().share.blind)
	}
}

// TestFdTrackerShareBookkeeping drives the tracker directly through hand-overs,
// unlinks and detaches with entries in both maps, checking the invariants after
// every step, that entries and ages travel with a handed-over table, and that
// the blind mark moves with it.
func TestFdTrackerShareBookkeeping(t *testing.T) {
	tr := newFDTracker(nil)
	tr.set(3, 10, file.NewFd(3, "/a", syscall.O_RDONLY))
	tr.setProcFdCache(8, 10, file.NewFd(8, "/cached", syscall.O_RDONLY))
	for _, child := range []uint32{11, 12, 13} {
		tr.shareTable(child, 10)
		assertFdShareInvariants(t, tr)
	}

	tr.deletePid(10) // holder exits: heir is the smallest sharer, 11
	assertFdShareInvariants(t, tr)
	for _, pid := range []uint32{11, 12, 13} {
		if _, ok := tr.get(3, pid); !ok {
			t.Errorf("pid %d lost fd 3 when the holder exited", pid)
		}
		if _, ok := tr.cachedProcFdFile(8, pid); !ok {
			t.Errorf("pid %d lost its cached fd 8 when the holder exited", pid)
		}
	}
	if _, ok := tr.get(3, 10); ok {
		t.Error("the exited holder still resolves the table")
	}

	tr.markBlind(12)
	tr.deletePid(11) // the heir exits: the blind table moves to 12
	assertFdShareInvariants(t, tr)
	if !tr.isBlind(12) || !tr.isBlind(13) {
		t.Error("the blind mark did not travel with the table")
	}

	tr.detachShared(13) // leaves the blind group: private, not blind, empty
	if tr.isBlind(13) || !tr.isBlind(12) {
		t.Errorf("after detach: blind(13)=%v blind(12)=%v, want false true", tr.isBlind(13), tr.isBlind(12))
	}
	assertFdShareInvariants(t, tr)

	tr.deletePid(12)
	tr.deletePid(13)
	if len(tr.files) != 0 || len(tr.procFdCache) != 0 || len(tr.pidIndex) != 0 ||
		len(tr.share.tableOf) != 0 || len(tr.share.sharers) != 0 || len(tr.share.blind) != 0 {
		t.Errorf("state left after every user exited: files=%d cache=%d index=%d tableOf=%v sharers=%v blind=%v",
			len(tr.files), len(tr.procFdCache), len(tr.pidIndex), tr.share.tableOf, tr.share.sharers, tr.share.blind)
	}
}

// TestShareTableIgnoresItself: a record naming the task as its own creator is
// malformed and must not make it alias itself.
func TestShareTableIgnoresItself(t *testing.T) {
	tr := newFDTracker(nil)
	tr.set(3, 10, file.NewFd(3, "/a", syscall.O_RDONLY))
	tr.shareTable(10, 10)
	if _, ok := tr.get(3, 10); !ok || tr.sharesTable(10) {
		t.Fatal("a self-share changed the table")
	}
}

// TestUnsharedTraceKeepsTheFastPath pins that an ordinary trace never allocates
// the sharing state: tableID is the identity and the maps stay nil.
func TestUnsharedTraceKeepsTheFastPath(t *testing.T) {
	tr := newFDTracker(nil)
	tr.set(3, 10, file.NewFd(3, "/a", syscall.O_RDONLY))
	tr.deletePid(10)
	if tr.tableID(10) != 10 || tr.share.tableOf != nil || tr.share.sharers != nil || tr.share.blind != nil {
		t.Fatalf("sharing state allocated without a CLONE_FILES record: %+v", tr.share)
	}
}

// TestCloneFilesTableCountsOnceTowardTheCaps: a shared table is one set of
// entries, however many processes use it.
func TestCloneFilesTableCountsOnceTowardTheCaps(t *testing.T) {
	tr := newFDTracker(nil)
	for fd := int32(3); fd < 13; fd++ {
		tr.set(fd, 10, file.NewFd(fd, "/f"+strings.Repeat("x", int(fd)), syscall.O_RDONLY))
	}
	for child := uint32(20); child < 60; child++ {
		tr.shareTable(child, 10)
	}
	if len(tr.files) != 10 {
		t.Fatalf("%d entries for one shared table of 10 descriptors", len(tr.files))
	}
}
