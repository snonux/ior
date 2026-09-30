package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task dr2. Under -comm, tracepointEntered used to recycle the enter of every
// non-open/exec syscall whose tid had no cached comm, so its exit handler never
// ran and the fd table never changed. Every fresh thread is in that state until
// its comm is known (the task_newtask record seeds it, but a lost record, a
// failed attach or a recycled tid whose exit record was lost still leave the
// tid uncached). A thread that closed or re-pointed a descriptor of the shared
// table was therefore invisible, and later rows of a thread the filter *does*
// want kept the closed file's name.
//
// The fd table is per process, not per thread, and handleFdExit & co. apply
// their state change before the pair filter precisely so a row the run does
// not want still leaves the table correct. The enter gate contradicted that
// rule; it is gone, and the exit-side filter (finishPair, comm "" matches no
// -comm pattern) is what drops the unwanted thread's own row.

const (
	gateWantedComm = "curl"
	gateWorkerTid  = execCommTid + 1 // same process, no cached comm
	gateFdSource   = 3
	gateFdOther    = 4
	gateFdDup      = 5
	gateOpenedName = "/etc/hostname"
	gateOtherName  = "/tmp/other.txt"
)

// gateWorkerPair builds one enter/exit record pair issued by the uncached
// worker thread, and (via check) says what the wanted thread must then see.
type gateWorkerPair func(t *testing.T) (enterRaw, exitRaw []byte)

// gateCase is one fd-table-changing syscall run by the worker thread.
type gateCase struct {
	name string
	// worker builds the worker thread's syscall.
	worker gateWorkerPair
	// readFd is the descriptor the wanted thread reads afterwards.
	readFd int32
	// wantName is the name the read must report; "" means "must not be the
	// closed file" (the descriptor is gone, so no traced name is left).
	wantName string
}

func gateCases() []gateCase {
	const t0 = defaulTime + 1000
	return []gateCase{
		{
			name: "close",
			worker: func(t *testing.T) ([]byte, []byte) {
				_, enter := makeEnterFdEvent(t, t0, execCommPid, gateWorkerTid, gateFdSource, types.SYS_ENTER_CLOSE)
				_, exit := makeExitCloseEvent(t, t0+100, execCommPid, gateWorkerTid, 0)
				return enter, exit
			},
			readFd: gateFdSource,
		},
		{
			name: "close_range",
			worker: func(t *testing.T) ([]byte, []byte) {
				_, enter := makeEnterTwoFdEvent(t, t0, execCommPid, gateWorkerTid,
					gateFdSource, gateFdSource, 0, types.SYS_ENTER_CLOSE_RANGE)
				_, exit := makeExitRetEvent(t, t0+100, execCommPid, gateWorkerTid, types.SYS_EXIT_CLOSE_RANGE, 0)
				return enter, exit
			},
			readFd: gateFdSource,
		},
		{
			name: "dup2 onto the open descriptor",
			worker: func(t *testing.T) ([]byte, []byte) {
				_, enter := makeEnterFdEvent(t, t0, execCommPid, gateWorkerTid, gateFdOther, types.SYS_ENTER_DUP2)
				_, exit := makeExitRetEvent(t, t0+100, execCommPid, gateWorkerTid, types.SYS_EXIT_DUP2, gateFdSource)
				return enter, exit
			},
			readFd:   gateFdSource,
			wantName: gateOtherName,
		},
		{
			name: "dup3 onto the open descriptor",
			worker: func(t *testing.T) ([]byte, []byte) {
				_, enter := makeEnterDup3Event(t, t0, execCommPid, gateWorkerTid, gateFdOther, syscall.O_CLOEXEC)
				_, exit := makeExitRetEvent(t, t0+100, execCommPid, gateWorkerTid, types.SYS_EXIT_DUP3, gateFdSource)
				return enter, exit
			},
			readFd:   gateFdSource,
			wantName: gateOtherName,
		},
		{
			name: "fcntl F_DUPFD",
			worker: func(t *testing.T) ([]byte, []byte) {
				_, enter := makeEnterFcntlEvent(t, t0, execCommPid, gateWorkerTid, gateFdOther, syscall.F_DUPFD, 0)
				_, exit := makeExitRetEvent(t, t0+100, execCommPid, gateWorkerTid, types.SYS_EXIT_FCNTL, gateFdDup)
				return enter, exit
			},
			readFd:   gateFdDup,
			wantName: gateOtherName,
		},
	}
}

// newGateEventLoop builds a -comm curl loop whose hermetic resolver never
// answers, so a tid is named only by a record: the main thread by the comm in
// its open payload, the worker not at all.
func newGateEventLoop(t *testing.T) (el *eventLoop, warnings *[]string) {
	t.Helper()
	el = mustNewEventLoop(t, eventLoopConfig{
		filter:       globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: gateWantedComm}},
		commResolver: newHermeticCommResolver(),
	})
	t.Cleanup(el.commResolver.shutdown)
	got := []string{}
	el.SetWarningCallback(func(message string) { got = append(got, message) })
	return el, &got
}

// openAsWantedThread opens name on fd through the wanted main thread, which is
// kept by the comm filter and names the tid via the open payload.
func openAsWantedThread(t *testing.T, el *eventLoop, name string, fd int64) {
	t.Helper()
	ep := feedOpenPair(t, el, name, gateWantedComm, fd)
	if ep == nil {
		t.Fatalf("the wanted thread's open of %s was dropped", name)
	}
	ep.Recycle()
}

// wantedThreadRead feeds a read on fd by the wanted main thread and returns the
// emitted pair (nil when dropped).
func wantedThreadRead(t *testing.T, el *eventLoop, fd int32) *event.Pair {
	t.Helper()
	return feedFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ, fd, 7,
		defaulTime+5000, defaulTime+5100)
}

func TestUncachedThreadFdChangesReachTheFdTableUnderCommFilter(t *testing.T) {
	for _, tc := range gateCases() {
		t.Run(tc.name, func(t *testing.T) {
			el, _ := newGateEventLoop(t)
			openAsWantedThread(t, el, gateOpenedName, gateFdSource)
			openAsWantedThread(t, el, gateOtherName, gateFdOther)
			if _, cached := el.cachedComm(gateWorkerTid); cached {
				t.Fatal("fixture broken: the worker thread's comm must not be cached")
			}

			// The worker's own row is dropped by the comm filter (no comm
			// matches), but the syscall must have taken effect on the table.
			enterRaw, exitRaw := tc.worker(t)
			if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
				ep.Recycle()
				t.Fatalf("the uncached worker's row survived -comm %s", gateWantedComm)
			}

			ep := wantedThreadRead(t, el, tc.readFd)
			if ep == nil {
				t.Fatal("the wanted thread's read was dropped")
			}
			defer ep.Recycle()
			got := ep.File.Name()
			if tc.wantName != "" && got != tc.wantName {
				t.Fatalf("read on fd %d reports %q, want %q", tc.readFd, got, tc.wantName)
			}
			if tc.wantName == "" && got == gateOpenedName {
				t.Fatalf("read on fd %d still reports the closed file %q", tc.readFd, got)
			}
		})
	}
}

// TestUncachedThreadRowsAreStillFilteredByComm keeps the drop honest: with the
// enter gate gone, the -comm filter for an uncached tid rests on the exit
// checkpoint alone, so a syscall that changes no fd state must still not be
// emitted, and its enter must not be left parked.
func TestUncachedThreadRowsAreStillFilteredByComm(t *testing.T) {
	el, warnings := newGateEventLoop(t)
	openAsWantedThread(t, el, gateOpenedName, gateFdSource)

	_, enterRaw := makeEnterFdEvent(t, defaulTime+1000, execCommPid, gateWorkerTid, gateFdSource, types.SYS_ENTER_READ)
	_, exitRaw := makeExitRetEvent(t, defaulTime+1100, execCommPid, gateWorkerTid, types.SYS_EXIT_READ, 7)
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		ep.Recycle()
		t.Fatalf("an uncached thread's read was emitted under -comm %s", gateWantedComm)
	}
	if n := len(el.pairs.enters); n != 0 {
		t.Fatalf("%d enter(s) left parked after the exit", n)
	}
	if len(*warnings) != 0 {
		t.Fatalf("a routine uncached tid must not raise warnings, got %q", *warnings)
	}
}

// TestUncachedThreadEnterIsParkedNotRecycled pins the enter-side contract
// directly: under -comm an enter with no cached comm is stored for its exit,
// exactly as one with a cached, non-matching comm is.
func TestUncachedThreadEnterIsParkedNotRecycled(t *testing.T) {
	el, warnings := newGateEventLoop(t)
	var recycles int32
	el.tracepointEntered(&recycleCountingEvent{tid: gateWorkerTid, recycleCount: &recycles})
	if recycles != 0 {
		t.Fatalf("enter recycled %d time(s), want it parked for its exit", recycles)
	}
	if _, ok := el.pairs.consume(gateWorkerTid); !ok {
		t.Fatal("the enter was not parked")
	}
	if len(*warnings) != 0 {
		t.Fatalf("unexpected warnings %q", *warnings)
	}
}
