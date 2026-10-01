// Package parkwait lets a test wait until a goroutine is provably parked on a
// lock inside a given function, instead of sleeping and hoping the scheduler
// got it there.
//
// The proof comes from the runtime's own goroutine dump (runtime.Stack with
// all=true): a goroutine blocked on a sync primitive carries its wait reason
// in its header, e.g. "goroutine 7 [sync.RWMutex.RLock]:", above its frames.
// That observes "this goroutine reached the lock and is waiting for it"
// without a test seam in production code. A goroutine that merely started, or
// that is still spinning before it parks, does not count, so a test that
// advances shared state after Await returns knows the waiter has not yet read
// it - on any host load, which a fixed sleep cannot promise.
//
// What is matched is a function name, not a goroutine instance: the dump
// cannot say "the goroutine this test started". Two filters narrow it down.
// Only goroutines whose own "created by ... in goroutine N" line names the
// goroutine calling Count/Run are counted, so a goroutine leaked by another
// test (started by that test's goroutine) never satisfies the wait. The
// creator is whichever goroutine executed the go statement, so the test
// goroutine must start the waited-for goroutine on itself: a go statement in
// the test function, or in a helper or library call made synchronously on the
// test goroutine (errgroup.Go called on it, for instance), all qualify; a
// goroutine started from inside another goroutine does not, and a wait for it
// times out, naming how many goroutines parked in the frame it ignored as
// started elsewhere. Count and Run must likewise be called on the test
// goroutine itself. The Baseline then excludes goroutines of the same test
// goroutine that were already parked there when it was taken.
//
// Two cases remain unfiltered, and the test controls both, so it must avoid
// them: a second goroutine the same test goroutine starts into the same frame
// after the baseline, and a goroutine it started before the baseline that had
// not parked in the frame yet when the baseline was taken (the baseline does
// not count it, so once it parks there it satisfies the wait just as the
// intended goroutine would). Take the baseline only once every earlier
// goroutine of the test that can reach the frame is parked there or finished.
//
// It is a non-test package only because _test.go helpers cannot be shared
// across packages; nothing outside tests should import it.
package parkwait

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Wait reasons as they appear in a goroutine dump header. Semacquire is the
// generic reason older toolchains printed for every sync wait; current ones
// name the primitive. Pass the reasons that fit the lock being waited on.
const (
	MutexLock    = "sync.Mutex.Lock"
	RWMutexRLock = "sync.RWMutex.RLock"
	// RWMutexLock is a writer waiting for readers to leave (the uncontended
	// writer mutex is taken first, so a lone writer parks with this reason).
	RWMutexLock = "sync.RWMutex.Lock"
	Semacquire  = "semacquire"
)

// defaultTimeout bounds a failing Await. It is not a synchronisation guess:
// a passing run returns on the first poll that sees the goroutine parked. Each
// poll is a full dump of every goroutine (which stops the world, and costs
// more than the poll interval once a test binary has many goroutines) plus a
// pollInterval sleep, so that is typically a few polls, i.e. well under a
// second even on a loaded host; only a run whose goroutine never parks waits
// this long.
const defaultTimeout = 10 * time.Second

// pollInterval spaces the goroutine dumps; each dump stops the world briefly,
// so polling flat out would slow the very goroutine being waited for.
const pollInterval = 200 * time.Microsecond

// Count returns how many goroutines started by the calling goroutine are
// currently parked with one of the given wait reasons and have frame (a
// substring such as "(*aggregateDrainer).SwapFilter") in their own stack: the
// function and file:line lines between the goroutine's header and its
// "created by" line. The "created by" line itself (which names the creating
// function) and, under GODEBUG=tracebackancestors, the ancestor stacks below
// it are not searched, so a goroutine merely started from inside frame does
// not count. Goroutines started by any other goroutine are ignored (see the
// package doc), so call it from the goroutine that starts the waiter.
func Count(frame string, reasons ...string) int {
	return countCreatedBy(createdBySuffix(), frame, reasons)
}

// countCreatedBy counts the goroutines in a full dump that are parked in frame
// with one of reasons and were created by creator (see createdBySuffix).
func countCreatedBy(creator, frame string, reasons []string) int {
	mine, _ := countParked(dumpAll(), creator, frame, reasons)
	return mine
}

// countParked splits a full goroutine dump into per-goroutine blocks and
// counts those parked in frame with one of reasons (see parkedIn): mine were
// created by creator, others by any other goroutine. A goroutine without a
// "created by" line (the main goroutine) is in neither count.
func countParked(dump []byte, creator, frame string, reasons []string) (mine, others int) {
	for _, g := range strings.Split(string(dump), "\n\n") {
		createdBy, ok := parkedIn(g, frame, reasons)
		switch {
		case !ok:
		case strings.HasSuffix(createdBy, creator):
			mine++
		default:
			others++
		}
	}
	return mine, others
}

// parkedIn reports whether the goroutine dump block g has one of reasons in
// its header and frame in its own stack, and returns its "created by" line
// (without the trailing newline) for the creator check. The own stack ends at
// that line: what follows is the creation site and, with tracebackancestors,
// "[originating from goroutine N]:" ancestor stacks, neither of which says
// where this goroutine is parked.
func parkedIn(g, frame string, reasons []string) (createdBy string, ok bool) {
	header, rest, _ := strings.Cut(g, "\n")
	if !hasAny(header, reasons) {
		return "", false
	}
	stack, created, found := strings.Cut(rest, "\ncreated by ")
	if !found || !strings.Contains(stack, frame) {
		return "", false
	}
	createdBy, _, _ = strings.Cut(created, "\n")
	return "created by " + createdBy, true
}

// createdBySuffix returns the tail of the "created by <func> in goroutine N"
// line that every goroutine started by the calling goroutine carries in a
// dump. countParked matches it as a suffix of that one line, which keeps
// goroutine 35 from matching goroutine 350 (and the ancestor lines below it
// out of the comparison).
func createdBySuffix() string {
	buf := make([]byte, 64)
	buf = buf[:runtime.Stack(buf, false)] // "goroutine 35 [running]:\n..."
	id, _, _ := strings.Cut(strings.TrimPrefix(string(buf), "goroutine "), " ")
	return " in goroutine " + id
}

// dumpAll returns the stacks of all goroutines, growing the buffer until the
// dump fits (runtime.Stack truncates silently when it does not).
func dumpAll() []byte {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}

func hasAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Await describes one wait: until more than Baseline goroutines started by
// the goroutine calling Run are parked with one of Reasons inside Frame. Take
// Baseline from Count, on that same goroutine, before starting the waited-for
// goroutine, so goroutines parked there earlier do not satisfy the wait (the
// package doc lists the goroutines a baseline cannot exclude).
type Await struct {
	Frame    string
	Reasons  []string
	Baseline int
	// Done, if non-nil, is closed by the waited-for goroutine when it
	// finishes; closing before it parked means it never waited for the lock,
	// and the test fails with DoneMsg (default: "goroutine finished before
	// parking in <Frame>").
	Done    <-chan struct{}
	DoneMsg string
	// TimeoutMsg prefixes the failure message when the goroutine never parks
	// within Timeout (default defaultTimeout, 10s).
	TimeoutMsg string
	Timeout    time.Duration
}

// Run polls until the wait is satisfied, failing tb (via Fatal, so call it
// from the test goroutine that started the waited-for goroutine) when Done
// closes first or the timeout expires.
func (a Await) Run(tb testing.TB) {
	tb.Helper()
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	creator := createdBySuffix()
	deadline := time.Now().Add(timeout)
	for {
		mine, others := countParked(dumpAll(), creator, a.Frame, a.Reasons)
		if mine > a.Baseline {
			return
		}
		select {
		case <-a.Done: // a nil Done blocks forever, so this case never fires
			tb.Fatal(a.doneMsg())
		default:
		}
		if time.Now().After(deadline) {
			tb.Fatal(a.timeoutMsg(timeout, others))
		}
		runtime.Gosched()
		time.Sleep(pollInterval) // poll interval, not a synchronisation guess
	}
}

// doneMsg is DoneMsg, or a default naming the frame so an Await without one
// does not fail with a blank message.
func (a Await) doneMsg() string {
	if a.DoneMsg != "" {
		return a.DoneMsg
	}
	return "goroutine finished before parking in " + a.Frame
}

// timeoutMsg is TimeoutMsg followed by what was waited for; without a
// TimeoutMsg the detail stands alone. ignored is how many goroutines were
// parked in the frame with a matching reason on the last poll but were
// started by another goroutine than the caller of Run: naming them keeps a
// waiter started from the wrong goroutine (which the creator filter rightly
// rejects) from reading as "nothing parked there".
func (a Await) timeoutMsg(timeout time.Duration, ignored int) string {
	detail := fmt.Sprintf("no goroutine started by the calling goroutine parked in %s with reason %v beyond the baseline %d after %v",
		a.Frame, a.Reasons, a.Baseline, timeout)
	if ignored > 0 {
		detail += fmt.Sprintf("; %d goroutine(s) parked in %s were started by other goroutines and are ignored", ignored, a.Frame)
	}
	if a.TimeoutMsg == "" {
		return detail
	}
	return a.TimeoutMsg + " (" + detail + ")"
}
