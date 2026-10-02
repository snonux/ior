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
// answer stamped with it outlives every close and every row. (The binding
// time of an answer promoted into the fd table was the third such use; task
// a23 removed the promotion, see storeFcntlFdFile.)

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
