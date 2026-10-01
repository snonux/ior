package internal

import (
	"sync"
	"syscall"
	"testing"

	"ior/internal/file"
	"ior/internal/types"
)

// Task nr2, review hardening: two properties of the shared open file
// description that the main ofdshare tests do not reach.
//
//   - The procfs cache is a second place descriptors live in. A fork inherits
//     its entries with FdFile.Dup, so a descriptor the parent only ever knew
//     through procfs must share its status word with the child's copy exactly
//     like a traced one (a Detach there would silently make the two diverge).
//   - A pair that is emitted leaves the event-loop goroutine (TUI, aggregation,
//     the writer) while the loop keeps rewriting the live table. The emitted row
//     must therefore own its description; if it shared the live one, reading it
//     would race with F_SETFL/F_SETFD/dup. The race detector is the oracle.

const (
	procfsCachedFd   = int32(9)
	procfsCachedFd2  = int32(10)
	procfsCachedName = "/var/log/pre-attach.log"
)

// feedSetflOn feeds fcntl(fd, F_SETFL, flags) as process pid and returns once the
// event loop has handled it. Times only need to be unique per call.
func feedSetflOn(t *testing.T, el *eventLoop, pid uint32, fd int32, flags int32, now uint64) {
	t.Helper()
	_, enterRaw := makeEnterFcntlEvent(t, now, pid, pid, uint32(fd), syscall.F_SETFL, uint64(flags))
	_, exitRaw := makeExitRetEvent(t, now+100, pid, pid, types.SYS_EXIT_FCNTL, 0)
	feedRawPair(t, el, enterRaw, exitRaw).Recycle()
}

// wantReadFlags fails unless a read of fd by pid reports want.
func wantReadFlags(t *testing.T, el *eventLoop, pid uint32, fd int32, want int32, who string) {
	t.Helper()
	if got := feedReadOn(t, el, pid, pid, fd).Flags(); got != file.Flags(want) {
		t.Errorf("%s: fd %d reports flags %v, want %v", who, fd, got, file.Flags(want))
	}
}

// TestForkInheritedProcfsCacheEntriesShareTheStatusWord: the parent knows fd 9
// only through the procfs cache (opened before ior attached). After a fork the
// child's inherited copy and the parent's entry are one open file description:
// a F_SETFL by the child shows in the parent's rows and vice versa. Fd 10 is the
// negative control, a second description of the same file in the same
// processes, which no F_SETFL on fd 9 may reach.
func TestForkInheritedProcfsCacheEntriesShareTheStatusWord(t *testing.T) {
	const (
		plain = int32(syscall.O_WRONLY)
		later = int32(syscall.O_WRONLY | syscall.O_NONBLOCK)
		both  = int32(syscall.O_WRONLY | syscall.O_NONBLOCK | syscall.O_APPEND)
	)
	el := newTaskEventLoop(t, "")
	tr := el.fdState()
	tr.setProcFdCache(procfsCachedFd, forkParentPid, file.NewFd(procfsCachedFd, procfsCachedName, plain))
	tr.setProcFdCache(procfsCachedFd2, forkParentPid, file.NewFd(procfsCachedFd2, procfsCachedName, plain))
	feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, forkSigchld)
	if _, ok := tr.get(procfsCachedFd, forkChildPid); ok {
		t.Fatalf("fd %d must reach the child through the procfs cache only", procfsCachedFd)
	}

	feedSetflOn(t, el, forkChildPid, procfsCachedFd, later, forkStart+1000)
	wantReadFlags(t, el, forkParentPid, procfsCachedFd, later, "parent after the child's F_SETFL")
	wantReadFlags(t, el, forkChildPid, procfsCachedFd, later, "child after its own F_SETFL")

	feedSetflOn(t, el, forkParentPid, procfsCachedFd, both, forkStart+2000)
	wantReadFlags(t, el, forkChildPid, procfsCachedFd, both, "child after the parent's F_SETFL")

	// Negative control: the other description is untouched in both processes.
	wantReadFlags(t, el, forkParentPid, procfsCachedFd2, plain, "parent's independent fd")
	wantReadFlags(t, el, forkChildPid, procfsCachedFd2, plain, "child's independent fd")
}

// emittedRowRaceIterations bounds the loop-side mutations of the race test: far
// more than the race detector needs to see an unsynchronised pair of accesses,
// still milliseconds without it.
const emittedRowRaceIterations = 300

// TestEmittedRowIsRaceFreeAgainstLiveTableUpdates: an emitted row's File is read
// from another goroutine (Flags, Dup, as a TUI or writer would) while this
// goroutine, acting as the event loop, rewrites the live description the row was
// taken from (F_SETFL through a duplicate), the descriptor flag (F_SETFD) and the
// table (dup). Run under -race: a row that shared the live description, i.e. a
// freezePairForEmission that did not Detach, is reported as a DATA RACE.
func TestEmittedRowIsRaceFreeAgainstLiveTableUpdates(t *testing.T) {
	f := newOfdFeeder(t)
	f.openFile(ofdOrigFd, ofdName, ofdOpenFlags)
	f.dup(ofdOrigFd, ofdDupFd)
	row := f.fdPair(types.SYS_ENTER_READ, types.SYS_EXIT_READ, ofdOrigFd, 1)
	defer row.Recycle()
	emitted, ok := row.File.(*file.FdFile)
	if !ok {
		t.Fatalf("read reported %T, want *file.FdFile", row.File)
	}

	var started, done sync.WaitGroup
	start := make(chan struct{})
	started.Add(1)
	done.Add(1)
	go func() { // the consumer on the far side of the goroutine boundary
		defer done.Done()
		started.Done()
		<-start
		for i := 0; i < emittedRowRaceIterations; i++ {
			_ = emitted.Flags()
			_ = emitted.Dup(int32(100 + i%8)).Flags()
		}
	}()
	started.Wait()
	close(start)

	for i := 0; i < emittedRowRaceIterations; i++ {
		f.setfl(ofdDupFd, ofdSetflArg|int32(i&1)*syscall.O_APPEND).Recycle()
		f.fcntl(ofdOrigFd, syscall.F_SETFD, uint64(i&1), 0).Recycle()
		f.dup(ofdOrigFd, int32(50+i%8))
	}
	done.Wait()

	// The row still reports the moment it was emitted at.
	if got := emitted.Flags(); got != file.Flags(ofdOpenFlags) {
		t.Errorf("emitted row reports %v after the table moved on, want %v", got, file.Flags(ofdOpenFlags))
	}
}
