package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
)

// TestRepeatedGroupDeadRecordsCountOneDeath covers kernels whose tracepoint has
// no group_dead field: several threads of one exit_group can each read
// signal->live == 0 and each emit a group_dead=1 record. They are one process
// death and must move the counter once.
func TestRepeatedGroupDeadRecordsCountOneDeath(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(crossFd, crossPidA, file.NewFd(crossFd, "/tmp/dup-exit.txt", syscall.O_RDONLY))
	out := make(chan *event.Pair, 1)

	// Three threads of one process, microseconds apart, one arriving
	// slightly out of order as records from different CPUs can.
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+2_000, crossPidA, crossTidA), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+1_000, crossPidA, crossTidA+1), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+3_000, crossPidA, crossTidA+2), out)

	if el.numGroupDeadExits != 1 {
		t.Fatalf("numGroupDeadExits = %d for one process death reported by three threads, want 1", el.numGroupDeadExits)
	}
	if _, ok := el.fdState().get(crossFd, crossPidA); ok {
		t.Fatalf("pid %d fd %d still tracked after the process exited", crossPidA, crossFd)
	}
}

// TestGroupDeadOfDifferentPidsAreCountedSeparately is the negative test: the
// dedup is per pid, so simultaneous deaths of distinct processes all count.
func TestGroupDeadOfDifferentPidsAreCountedSeparately(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)

	el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+1, crossPidB, crossTidB), out)

	if el.numGroupDeadExits != 2 {
		t.Fatalf("numGroupDeadExits = %d for two distinct processes, want 2", el.numGroupDeadExits)
	}
}

// TestRecycledPidDeathIsCountedAgain is the other negative test: once the dedup
// window has passed, the same pid dying again is a new process and counts.
func TestRecycledPidDeathIsCountedAgain(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)

	el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+2*groupDeadDedupWindowNs, crossPidA, crossTidA), out)

	if el.numGroupDeadExits != 2 {
		t.Fatalf("numGroupDeadExits = %d for a recycled pid dying twice, want 2", el.numGroupDeadExits)
	}
}

// TestGroupDeadDedupMapStaysBounded checks that the per-pid memory is pruned:
// a process-churning trace must not grow it without limit.
func TestGroupDeadDedupMapStaysBounded(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)

	const deaths = 4 * groupDeadDedupPruneAt
	for i := uint32(0); i < deaths; i++ {
		// Each death is a full window after the previous one, so every
		// older entry is prunable.
		at := defaulTime + uint64(i)*2*groupDeadDedupWindowNs
		el.processRawEvent(makeProcessExitEvent(t, at, 1000+i, 1000+i), out)
	}

	if el.numGroupDeadExits != deaths {
		t.Fatalf("numGroupDeadExits = %d, want %d", el.numGroupDeadExits, deaths)
	}
	if got := len(el.recentGroupDead); got > groupDeadDedupPruneAt {
		t.Fatalf("recentGroupDead holds %d pids, want at most %d", got, groupDeadDedupPruneAt)
	}
}
