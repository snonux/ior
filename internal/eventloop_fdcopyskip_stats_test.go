package internal

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"ior/internal/file"
)

// fdCopySkipStatPrefix is the start of the end-of-run line that reports
// fdTracker.inheritSkipped (task ss2).
const fdCopySkipStatPrefix = "\tfd-table copies skipped: "

// finishedStats returns el's end-of-run statistics as stats() renders them
// after the loop has stopped (done closed, one second of run time).
func finishedStats(t *testing.T, el *eventLoop) string {
	t.Helper()
	el.startTime = time.Now().Add(-time.Second)
	close(el.done)
	return el.stats()
}

// TestStatsReportsSkippedFdTableCopies: a fork whose parent tracks more than
// maxInheritedEntries entries copies nothing, and the statistics say how many
// copies were skipped, so rows showing the procfs spelling of an inherited
// descriptor can be explained.
func TestStatsReportsSkippedFdTableCopies(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	fds := el.fdState()
	for fd := int32(3); fd < 3+maxInheritedEntries+1; fd++ {
		fds.set(fd, forkParentPid, file.NewFd(fd, "/f", syscall.O_RDONLY))
	}
	fds.inherit(forkParentPid, forkChildPid)
	fds.inherit(forkParentPid, forkChildPid+1)
	if fds.inheritSkipped != 2 {
		t.Fatalf("inheritSkipped = %d, want 2", fds.inheritSkipped)
	}

	stats := finishedStats(t, el)
	want := fdCopySkipStatPrefix + "2 (source table over " +
		strconv.Itoa(maxInheritedEntries) + " entries or fd table full; descriptors resolved through procfs)\n"
	if !strings.Contains(stats, want) {
		t.Fatalf("stats lack the skipped-copy line %q:\n%s", want, stats)
	}
	// The line belongs to the indented block, after the fixed lines.
	if strings.Index(stats, "\tgroup-dead exits: ") > strings.Index(stats, want) {
		t.Fatalf("skipped-copy line precedes the fixed lines:\n%s", stats)
	}
}

// TestStatsOmitSkippedFdTableCopiesWhenNoneWereSkipped is the negative case:
// like the other conditional lines (rows lost, records discarded at stop) the
// line is hidden on a run without skips, including one whose forks did copy.
func TestStatsOmitSkippedFdTableCopiesWhenNoneWereSkipped(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	fds := el.fdState()
	fds.set(3, forkParentPid, file.NewFd(3, "/f", syscall.O_RDONLY))
	fds.inherit(forkParentPid, forkChildPid)
	if fds.inheritSkipped != 0 {
		t.Fatalf("inheritSkipped = %d after a copy that fits, want 0", fds.inheritSkipped)
	}

	if stats := finishedStats(t, el); strings.Contains(stats, "fd-table copies skipped") {
		t.Fatalf("stats show a skipped-copy line although nothing was skipped:\n%s", stats)
	}
}
