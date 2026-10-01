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
// It is a non-test package only because _test.go helpers cannot be shared
// across packages; nothing outside tests should import it.
package parkwait

import (
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
	RWMutexLock  = "sync.RWMutex.Lock"
	Semacquire   = "semacquire"
)

// defaultTimeout bounds a failing Await. It is not a synchronisation guess:
// a passing run returns as soon as the goroutine parks, usually within
// microseconds; only a run whose goroutine never parks waits this long.
const defaultTimeout = 10 * time.Second

// pollInterval spaces the goroutine dumps; each dump stops the world briefly,
// so polling flat out would slow the very goroutine being waited for.
const pollInterval = 200 * time.Microsecond

// Count returns how many goroutines are currently parked with one of the
// given wait reasons and have frame (a substring such as
// "(*aggregateDrainer).SwapFilter") somewhere in their stack.
func Count(frame string, reasons ...string) int {
	count := 0
	for _, g := range strings.Split(string(dumpAll()), "\n\n") {
		header, _, _ := strings.Cut(g, "\n")
		if hasAny(header, reasons) && strings.Contains(g, frame) {
			count++
		}
	}
	return count
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

// Await describes one wait: until more than Baseline goroutines are parked
// with one of Reasons inside Frame. Take Baseline from Count before starting
// the goroutine, so goroutines parked there earlier do not satisfy the wait.
type Await struct {
	Frame    string
	Reasons  []string
	Baseline int
	// Done, if non-nil, is closed by the waited-for goroutine when it
	// finishes; closing before it parked means it never waited for the lock,
	// and the test fails with DoneMsg.
	Done    <-chan struct{}
	DoneMsg string
	// TimeoutMsg is the failure message when the goroutine never parks
	// within Timeout (default 10s).
	TimeoutMsg string
	Timeout    time.Duration
}

// Run polls until the wait is satisfied, failing tb (via Fatal, so call it
// from the test goroutine) when Done closes first or the timeout expires.
func (a Await) Run(tb testing.TB) {
	tb.Helper()
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	deadline := time.Now().Add(timeout)
	for Count(a.Frame, a.Reasons...) <= a.Baseline {
		select {
		case <-a.Done: // a nil Done blocks forever, so this case never fires
			tb.Fatal(a.DoneMsg)
		default:
		}
		if time.Now().After(deadline) {
			tb.Fatalf("%s (no goroutine parked in %s with reason %v after %v)", a.TimeoutMsg, a.Frame, a.Reasons, timeout)
		}
		runtime.Gosched()
		time.Sleep(pollInterval) // poll interval, not a synchronisation guess
	}
}
