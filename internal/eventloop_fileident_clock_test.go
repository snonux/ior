package internal

import (
	"math"
	"syscall"
	"testing"

	"ior/internal/file"
)

// Task 603, procfs read times that cannot be ordered against the records: the
// sentinel of a failed clock read (bootClockNs returns math.MaxUint64) and
// every read time while the offset of ior's time namespace is unknown, which
// may put them all in the records' future. The identity rules treat a later
// read time as "the number came to name this file later" and keep state on
// it, so such a time must count as none (fdTracker.identReadAt); otherwise an
// entry or answer stamped with it outlives every close and every row.

// unusableReadTime is one way a read time cannot be used: its value and
// whether the boot-clock offset is unknown.
type unusableReadTime struct {
	name    string
	readNs  uint64
	unknown bool
}

var unusableReadTimes = []unusableReadTime{
	{name: "failed clock read", readNs: math.MaxUint64},
	{name: "unknown time-namespace offset", readNs: 1 << 62, unknown: true},
}

const clockPid = absentPidBase + 7400

// clockTracker returns the fd tracker of a capturing run whose boot-clock
// offset is unknown or not, as rt says.
func clockTracker(t *testing.T, rt unusableReadTime) *fdTracker {
	t.Helper()
	tr := identLoop(t).fdState()
	tr.readClockUnknown = rt.unknown
	return tr
}

// cachedAnswerOf caches a procfs answer on fd 5 of clockPid that describes
// the file ident and was read at readNs.
func cachedAnswerOf(tr *fdTracker, ident uint32, readNs uint64) *file.FdFile {
	answer := file.NewFd(5, "/data/cached.txt", syscall.O_RDWR)
	answer.SetIdent(ident)
	tr.setProcFdCacheRead(5, clockPid, answer, readNs)
	return answer
}

// A procfs answer promoted into the fd table (an fcntl on an untracked
// descriptor) is bound at the fcntl's exit when its read time is unusable:
// a close of its own file that entered after that releases it, and a later
// row of another file drops it as a stale binding.
func TestPromotedAnswerWithAnUnusableReadTimeIsBoundAtTheExit(t *testing.T) {
	for _, rt := range unusableReadTimes {
		t.Run(rt.name, func(t *testing.T) {
			tr := clockTracker(t, rt)
			tr.bindNs = 5000
			answer := cachedAnswerOf(tr, 4711, rt.readNs)
			tr.set(5, clockPid, answer)
			if answer.BoundAt() != 5000 {
				t.Fatalf("promoted answer bound at %d, want the exit 5000", answer.BoundAt())
			}
			tr.closeIdentified(5, clockPid, 4711, 6000)
			if _, kept := tr.get(5, clockPid); kept {
				t.Fatalf("a close of its own file left the entry in the table")
			}

			again := cachedAnswerOf(tr, 4711, rt.readNs)
			tr.set(5, clockPid, again)
			if _, ok := tr.trackedFile(5, clockPid, 4712, 6000); ok || tr.staleBindings != 1 {
				t.Fatalf("a later row of another file kept the entry (ok=%v, staleBindings=%d)",
					ok, tr.staleBindings)
			}
		})
	}
}

// A close of one file keeps a cached answer of another only when that answer
// is known to have been read after the close entered. An unusable read time
// is not known to be anything: the answer goes, and is read again if needed.
func TestCloseForgetsAnAnswerWithAnUnusableReadTime(t *testing.T) {
	for _, rt := range unusableReadTimes {
		t.Run(rt.name, func(t *testing.T) {
			tr := clockTracker(t, rt)
			cachedAnswerOf(tr, 4712, rt.readNs)
			tr.closeIdentified(5, clockPid, 4711, 1000)
			if _, cached := tr.cachedProcFdFile(5, clockPid); cached {
				t.Fatalf("answer read at %d survived the close", rt.readNs)
			}
		})
	}
	tr := clockTracker(t, unusableReadTime{})
	cachedAnswerOf(tr, 4712, 2000)
	tr.closeIdentified(5, clockPid, 4711, 1000)
	if _, cached := tr.cachedProcFdFile(5, clockPid); !cached {
		t.Fatalf("control: an answer of another file read after the close went")
	}
}
