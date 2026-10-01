package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task nr2: the status flags of a descriptor (O_APPEND, O_NONBLOCK, ...) belong
// to the open file description, which dup/dup2/dup3/F_DUPFD (and fork) share, so
// an fcntl(F_SETFL) through any one of the descriptors changes what all of them
// report. FD_CLOEXEC belongs to the descriptor alone, and a second open(2) of
// the same path is a new open file description that shares nothing. Before the
// fix FdFile.Dup copied the flag word, so F_SETFL updated one table entry and
// every other descriptor of the description kept the stale word.

const (
	ofdPid        = execCommPid
	ofdOrigFd     = int32(31)
	ofdDupFd      = int32(32)
	ofdName       = "/tmp/ofd-share.txt"
	ofdOpenFlags  = int32(syscall.O_WRONLY | syscall.O_CREAT | syscall.O_TRUNC)
	ofdSetflFlags = int32(syscall.O_APPEND | syscall.O_NONBLOCK)
	// What the model reports after F_SETFL(O_APPEND|O_NONBLOCK) on a descriptor
	// opened O_WRONLY|O_CREAT|O_TRUNC: the setting adds the two settable bits,
	// the access mode and the flags as open() reported them stay as they were.
	// The kernel's own F_GETFL word would lack O_CREAT|O_TRUNC (it drops the
	// open-only flags from f_flags, 0106001); the model keeps them until an
	// F_GETFL replaces the whole word (see the F_GETFL refresh test below).
	ofdAfterSetfl = ofdOpenFlags | ofdSetflFlags
	// ofdSetflArg is what a caller passes: F_GETFL's word with the new bits ORed
	// in, so the access mode is part of the argument too.
	ofdSetflArg = ofdSetflFlags | int32(syscall.O_WRONLY)
)

// ofdFeeder feeds syscall pairs of one process with strictly increasing times,
// so no two pairs of a test can be mistaken for one another.
type ofdFeeder struct {
	t     *testing.T
	el    *eventLoop
	clock uint64
}

func newOfdFeeder(t *testing.T) *ofdFeeder {
	t.Helper()
	return &ofdFeeder{t: t, el: newFilteredEventLoop(t, globalfilter.Filter{}), clock: dupPairStart}
}

// times returns a fresh enter and exit timestamp.
func (f *ofdFeeder) times() (uint64, uint64) {
	f.clock += 1000
	return f.clock, f.clock + openPairLatency
}

// openFile registers descriptor fd through a real open enter/exit pair, so the
// handler (not the test) decides how the description is created.
func (f *ofdFeeder) openFile(fd int32, name string, flags int32) {
	f.t.Helper()
	ep := feedOpenPairWithFlags(f.t, f.el, name, ofdPid, execCommTid, int64(fd), flags)
	if ep == nil {
		f.t.Fatalf("open of %s produced no row", name)
	}
	ep.Recycle()
}

// fdPair feeds one fd-taking syscall (dup, dup2, read, close, ...).
func (f *ofdFeeder) fdPair(enter, exit types.TraceId, fd int32, ret int64) *event.Pair {
	f.t.Helper()
	start, end := f.times()
	ep := feedFdPair(f.t, f.el, enter, exit, fd, ret, start, end)
	if ep == nil {
		f.t.Fatalf("syscall pair on fd %d produced no row", fd)
	}
	return ep
}

// dup feeds dup(oldfd) returning newfd.
func (f *ofdFeeder) dup(oldfd, newfd int32) {
	f.t.Helper()
	f.fdPair(types.SYS_ENTER_DUP, types.SYS_EXIT_DUP, oldfd, int64(newfd)).Recycle()
}

// fcntl feeds one successful fcntl on fd and returns its row.
func (f *ofdFeeder) fcntl(fd int32, cmd uint32, arg uint64, ret int64) *event.Pair {
	f.t.Helper()
	start, end := f.times()
	_, enterRaw := makeEnterFcntlEvent(f.t, start, ofdPid, execCommTid, uint32(fd), cmd, arg)
	_, exitRaw := makeExitRetEvent(f.t, end, ofdPid, execCommTid, types.SYS_EXIT_FCNTL, ret)
	ep := feedRawPair(f.t, f.el, enterRaw, exitRaw)
	if ep == nil {
		f.t.Fatalf("fcntl(%d, %d) produced no row", fd, cmd)
	}
	return ep
}

// dup3 feeds dup3(oldfd, newfd, flags).
func (f *ofdFeeder) dup3(oldfd, newfd, flags int32) {
	f.t.Helper()
	start, end := f.times()
	_, enterRaw := makeEnterDup3Event(f.t, start, ofdPid, execCommTid, oldfd, flags)
	_, exitRaw := makeExitRetEvent(f.t, end, ofdPid, execCommTid, types.SYS_EXIT_DUP3, int64(newfd))
	feedRawPair(f.t, f.el, enterRaw, exitRaw).Recycle()
}

// setfl feeds fcntl(fd, F_SETFL, flags) and returns the fcntl row.
func (f *ofdFeeder) setfl(fd int32, flags int32) *event.Pair {
	f.t.Helper()
	return f.fcntl(fd, syscall.F_SETFL, uint64(flags), 0)
}

// readFlags feeds a read(fd) and returns the flags its row reports.
func (f *ofdFeeder) readFlags(fd int32) file.Flags {
	f.t.Helper()
	ep := f.fdPair(types.SYS_ENTER_READ, types.SYS_EXIT_READ, fd, 1)
	defer ep.Recycle()
	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		f.t.Fatalf("read(%d) reported %T, want *file.FdFile", fd, ep.File)
	}
	return fdFile.Flags()
}

// wantFlags fails unless a read on fd reports want.
func (f *ofdFeeder) wantFlags(fd int32, want int32) {
	f.t.Helper()
	if got := f.readFlags(fd); got != file.Flags(want) {
		f.t.Errorf("fd %d reports flags %v, want %v", fd, got, file.Flags(want))
	}
}

// ofdDupKind is one way of duplicating ofdOrigFd onto ofdDupFd.
type ofdDupKind struct {
	name string
	run  func(f *ofdFeeder)
	// cloexec is the FD_CLOEXEC state the duplicate starts with.
	cloexec bool
}

func ofdDupKinds() []ofdDupKind {
	return []ofdDupKind{
		{"dup", func(f *ofdFeeder) { f.dup(ofdOrigFd, ofdDupFd) }, false},
		{"dup2", func(f *ofdFeeder) {
			f.fdPair(types.SYS_ENTER_DUP2, types.SYS_EXIT_DUP2, ofdOrigFd, int64(ofdDupFd)).Recycle()
		}, false},
		{"dup3", func(f *ofdFeeder) { f.dup3(ofdOrigFd, ofdDupFd, 0) }, false},
		{"dup3 O_CLOEXEC", func(f *ofdFeeder) { f.dup3(ofdOrigFd, ofdDupFd, syscall.O_CLOEXEC) }, true},
		{"fcntl F_DUPFD", func(f *ofdFeeder) {
			f.fcntl(ofdOrigFd, syscall.F_DUPFD, 0, int64(ofdDupFd)).Recycle()
		}, false},
		{"fcntl F_DUPFD_CLOEXEC", func(f *ofdFeeder) {
			f.fcntl(ofdOrigFd, syscall.F_DUPFD_CLOEXEC, 0, int64(ofdDupFd)).Recycle()
		}, true},
	}
}

// TestSetflThroughADuplicateIsSeenThroughTheOriginal is the reproduction of the
// task: every duplicating syscall, F_SETFL on the duplicate, then a row on the
// original must report the changed status word (the pre-fix word was the stale
// open flags), with the access mode and open()'s other flags kept.
func TestSetflThroughADuplicateIsSeenThroughTheOriginal(t *testing.T) {
	for _, kind := range ofdDupKinds() {
		t.Run(kind.name, func(t *testing.T) {
			f := newOfdFeeder(t)
			f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
			kind.run(f)

			f.setfl(ofdDupFd, ofdSetflArg).Recycle()

			f.wantFlags(ofdOrigFd, ofdAfterSetfl)
			wantDup := ofdAfterSetfl
			if kind.cloexec {
				wantDup |= syscall.O_CLOEXEC
			}
			f.wantFlags(ofdDupFd, wantDup)
		})
	}
}

// TestSetflThroughTheOriginalIsSeenThroughTheDuplicate is the other direction,
// including a duplicate of a duplicate: the description is shared by the whole
// family, not by a source/copy pair.
func TestSetflThroughTheOriginalIsSeenThroughTheDuplicate(t *testing.T) {
	const thirdFd = int32(33)
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
	f.dup(ofdOrigFd, ofdDupFd)
	f.dup(ofdDupFd, thirdFd)

	f.setfl(ofdOrigFd, ofdSetflArg).Recycle()

	f.wantFlags(ofdDupFd, ofdAfterSetfl)
	f.wantFlags(thirdFd, ofdAfterSetfl)
	f.wantFlags(ofdOrigFd, ofdAfterSetfl)
}

// TestSetflClearingAFlagIsSharedToo: F_SETFL that clears O_NONBLOCK on one
// descriptor clears it for the others as well (no sticky bit on the copy).
func TestSetflClearingAFlagIsSharedToo(t *testing.T) {
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags|syscall.O_NONBLOCK)
	f.dup(ofdOrigFd, ofdDupFd)

	f.setfl(ofdOrigFd, int32(syscall.O_WRONLY)).Recycle()

	f.wantFlags(ofdDupFd, ofdOpenFlags)
}

// TestGetflRefreshIsSeenByEveryDuplicateAndLaterDups pins the second symptom of
// the task: F_GETFL on the original is the kernel's authoritative word, and a
// descriptor duplicated afterwards started from the stale word instead.
func TestGetflRefreshIsSeenByEveryDuplicateAndLaterDups(t *testing.T) {
	const laterFd = int32(34)
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
	f.dup(ofdOrigFd, ofdDupFd)
	f.setfl(ofdDupFd, ofdSetflArg).Recycle()

	// The kernel's word, as F_GETFL returns it (it includes O_LARGEFILE).
	kernelWord := ofdAfterSetfl | linuxOLargefile
	f.fcntl(ofdOrigFd, syscall.F_GETFL, 0, int64(kernelWord)).Recycle()

	f.dup(ofdOrigFd, laterFd)
	for _, fd := range []int32{ofdOrigFd, ofdDupFd, laterFd} {
		f.wantFlags(fd, kernelWord)
	}
}

// TestIndependentOpensOfOneFileDoNotShareFlags is the negative control: two
// open(2) calls of the same path make two open file descriptions, and a F_SETFL
// on a duplicate of one must not reach the other.
func TestIndependentOpensOfOneFileDoNotShareFlags(t *testing.T) {
	const secondFd = int32(40)
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
	f.openFile(secondFd, ofdName, ofdOpenFlags)
	f.dup(ofdOrigFd, ofdDupFd)

	f.setfl(ofdDupFd, ofdSetflArg).Recycle()

	f.wantFlags(ofdOrigFd, ofdAfterSetfl)
	f.wantFlags(secondFd, ofdOpenFlags)

	// And the other way round: the second open's own F_SETFL stays its own.
	f.setfl(secondFd, int32(syscall.O_WRONLY|syscall.O_NONBLOCK)).Recycle()
	f.wantFlags(ofdOrigFd, ofdAfterSetfl)
	f.wantFlags(ofdDupFd, ofdAfterSetfl)
}

// TestCloexecIsPerDescriptorNotShared: FD_CLOEXEC set or cleared through one
// descriptor (F_SETFD, dup3(O_CLOEXEC), F_GETFL's word) never shows on the
// others, while the status word stays shared in the same table.
func TestCloexecIsPerDescriptorNotShared(t *testing.T) {
	t.Run("F_SETFD on the duplicate", func(t *testing.T) {
		f := newOfdFeeder(t)
		f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
		f.dup(ofdOrigFd, ofdDupFd)

		f.fcntl(ofdDupFd, syscall.F_SETFD, syscall.FD_CLOEXEC, 0).Recycle()

		f.wantFlags(ofdOrigFd, ofdOpenFlags)
		f.wantFlags(ofdDupFd, ofdOpenFlags|syscall.O_CLOEXEC)
	})
	t.Run("F_SETFD on the original", func(t *testing.T) {
		f := newOfdFeeder(t)
		f.openFile(ofdOrigFd, ofdName, ofdOpenFlags|syscall.O_CLOEXEC)
		f.dup(ofdOrigFd, ofdDupFd)

		// dup cleared the duplicate's FD_CLOEXEC; setting it on the original
		// afterwards must not come back to the duplicate.
		f.fcntl(ofdOrigFd, syscall.F_SETFD, syscall.FD_CLOEXEC, 0).Recycle()

		f.wantFlags(ofdOrigFd, ofdOpenFlags|syscall.O_CLOEXEC)
		f.wantFlags(ofdDupFd, ofdOpenFlags)
	})
	t.Run("F_SETFL keeps each descriptor's own FD_CLOEXEC", func(t *testing.T) {
		f := newOfdFeeder(t)
		f.openFile(ofdOrigFd, ofdName, ofdOpenFlags|syscall.O_CLOEXEC)
		f.dup(ofdOrigFd, ofdDupFd)

		f.setfl(ofdDupFd, ofdSetflArg).Recycle()

		f.wantFlags(ofdOrigFd, ofdAfterSetfl|syscall.O_CLOEXEC)
		f.wantFlags(ofdDupFd, ofdAfterSetfl)
	})
	t.Run("F_GETFL on one keeps the other's FD_CLOEXEC", func(t *testing.T) {
		f := newOfdFeeder(t)
		f.openFile(ofdOrigFd, ofdName, ofdOpenFlags|syscall.O_CLOEXEC)
		f.dup(ofdOrigFd, ofdDupFd)

		// F_GETFL returns the status word without FD_CLOEXEC.
		f.fcntl(ofdDupFd, syscall.F_GETFL, 0, int64(ofdAfterSetfl)).Recycle()

		f.wantFlags(ofdOrigFd, ofdAfterSetfl|syscall.O_CLOEXEC)
		f.wantFlags(ofdDupFd, ofdAfterSetfl)
	})
}

// TestCloseOfOneDescriptorLeavesTheOther: closing a descriptor drops only its
// own table entry; the description lives on through the other, and a later
// F_SETFL still lands on it.
func TestCloseOfOneDescriptorLeavesTheOther(t *testing.T) {
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
	f.dup(ofdOrigFd, ofdDupFd)

	f.fdPair(types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, ofdOrigFd, 0).Recycle()
	if _, ok := f.el.fdState().get(ofdOrigFd, ofdPid); ok {
		t.Fatalf("fd %d is still tracked after close", ofdOrigFd)
	}
	f.setfl(ofdDupFd, ofdSetflArg).Recycle()

	f.wantFlags(ofdDupFd, ofdAfterSetfl)
}

// TestEmittedRowsKeepTheFlagsOfTheirMoment: a row that was already emitted must
// not change when a duplicate's F_SETFL rewrites the shared word afterwards (the
// pair holds a detached snapshot, not the live table entry).
func TestEmittedRowsKeepTheFlagsOfTheirMoment(t *testing.T) {
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
	f.dup(ofdOrigFd, ofdDupFd)

	before := f.fdPair(types.SYS_ENTER_READ, types.SYS_EXIT_READ, ofdOrigFd, 1)
	defer before.Recycle()
	f.setfl(ofdDupFd, ofdSetflArg).Recycle()

	assertPairFdFlags(t, before, ofdOrigFd, ofdOpenFlags)
}

// TestSetflRowReportsTheUpdatedWordOnTheDuplicate: the F_SETFL row itself
// shows the post-call state of the descriptor it names (existing behaviour,
// kept by the shared word).
func TestSetflRowReportsTheUpdatedWordOnTheDuplicate(t *testing.T) {
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
	f.dup(ofdOrigFd, ofdDupFd)

	ep := f.setfl(ofdDupFd, ofdSetflArg)
	defer ep.Recycle()

	assertPairFdFlags(t, ep, ofdDupFd, ofdAfterSetfl)
}

// TestForkedChildSharesTheStatusWordOfInheritedDescriptors: fork duplicates every
// descriptor onto the same open file descriptions, so the child's F_SETFL shows
// in the parent's table and vice versa; FD_CLOEXEC stays per copy.
func TestForkedChildSharesTheStatusWordOfInheritedDescriptors(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.fdState().set(3, forkParentPid, file.NewFd(3, ofdName, ofdOpenFlags))
	feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, forkSigchld)

	child, _ := el.fdState().get(3, forkChildPid)
	parent, _ := el.fdState().get(3, forkParentPid)
	child.(*file.FdFile).MergeFlags(int32(syscall.O_NONBLOCK), syscall.O_NONBLOCK)
	child.(*file.FdFile).MergeFlags(syscall.O_CLOEXEC, syscall.O_CLOEXEC)

	if !parent.Flags().Is(syscall.O_NONBLOCK) {
		t.Errorf("parent flags %v lack the O_NONBLOCK the child set on the shared description", parent.Flags())
	}
	if parent.Flags().Is(syscall.O_CLOEXEC) {
		t.Errorf("parent flags %v carry the child's FD_CLOEXEC", parent.Flags())
	}
}
