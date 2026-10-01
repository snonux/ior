package parkwait

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// readUnderLock takes the read lock, so a goroutine running it while the
// write lock is held parks in sync.RWMutex.RLock with this frame on its stack.
//
//go:noinline
func readUnderLock(mu *sync.RWMutex) {
	mu.RLock()
	defer mu.RUnlock()
}

// TestAwaitReturnsOnceTheGoroutineParks is the positive case: a reader held
// off by the write lock is observed parked inside readUnderLock, and drops
// out of the count again once the lock is released and it returns.
func TestAwaitReturnsOnceTheGoroutineParks(t *testing.T) {
	const frame = "parkwait.readUnderLock"
	var mu sync.RWMutex
	mu.Lock()
	baseline := Count(frame, RWMutexRLock, Semacquire)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readUnderLock(&mu)
	}()

	Await{
		Frame: frame, Reasons: []string{RWMutexRLock, Semacquire}, Baseline: baseline,
		Done: done, DoneMsg: "reader returned while the write lock was held",
	}.Run(t)
	mu.Unlock()
	<-done
	if n := Count(frame, RWMutexRLock, Semacquire); n != baseline {
		t.Fatalf("Count = %d after the reader returned, want the baseline %d", n, baseline)
	}
}

// TestCountIgnoresOtherWaitReasons checks the negative case: a goroutine
// inside the frame but parked for a reason not asked for (here a channel
// receive) does not count as parked on a lock.
func TestCountIgnoresOtherWaitReasons(t *testing.T) {
	const frame = "parkwait.waitOnChannel"
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		waitOnChannel(release)
	}()
	defer func() { close(release); <-done }()

	deadline := time.Now().Add(10 * time.Second)
	for Count(frame, "chan receive") == 0 { // wait until it is parked at all
		if time.Now().After(deadline) {
			t.Fatal("goroutine never parked on the channel")
		}
		time.Sleep(time.Millisecond)
	}
	if n := Count(frame, MutexLock, RWMutexRLock, Semacquire); n != 0 {
		t.Fatalf("Count = %d for a goroutine parked on a channel, want 0", n)
	}
}

//go:noinline
func waitOnChannel(release <-chan struct{}) { <-release }

// fakeTB records the failure Run reports instead of failing the real test.
// Like testing.T, Fatal ends the calling goroutine with runtime.Goexit, so
// Run must be driven from a goroutine of its own (see runAwait). Methods Run
// does not call fall through to the embedded nil testing.TB and would panic,
// which flags a Run that started using more of the interface.
type fakeTB struct {
	testing.TB
	failed bool
	msg    string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatal(args ...any) {
	f.failed, f.msg = true, fmt.Sprint(args...)
	runtime.Goexit()
}

// runAwait runs spawn and then a.Run on one fresh goroutine (so that goroutine
// is both the waiter's creator, as Run requires, and the one Fatal unwinds)
// and returns what the fake recorded. spawn returns the Await to run, filled
// in with the Done channel of the goroutine it started.
func runAwait(t *testing.T, spawn func() Await) *fakeTB {
	t.Helper()
	tb := &fakeTB{}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		spawn().Run(tb)
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("Await.Run neither returned nor failed")
	}
	return tb
}

// TestAwaitRunFailsWithTimeoutMsg covers the timeout path: a goroutine that
// never parks on the lock (it waits on a channel) fails the wait once the
// short Timeout expires, with TimeoutMsg plus the frame waited for.
func TestAwaitRunFailsWithTimeoutMsg(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	tb := runAwait(t, func() Await {
		go waitOnChannel(release)
		return Await{
			Frame: "parkwait.waitOnChannel", Reasons: []string{RWMutexRLock},
			TimeoutMsg: "never parked", Timeout: 20 * time.Millisecond,
		}
	})
	if !tb.failed {
		t.Fatal("Run returned although nothing parked on a lock")
	}
	for _, want := range []string{"never parked (", "no goroutine started by the calling goroutine parked in parkwait.waitOnChannel", "after 20ms"} {
		if !strings.Contains(tb.msg, want) {
			t.Errorf("failure %q does not contain %q", tb.msg, want)
		}
	}
	if strings.Contains(tb.msg, "ignored") {
		t.Errorf("failure %q mentions ignored goroutines although none parked in the frame", tb.msg)
	}
}

// TestAwaitRunFailsWithDoneMsg covers the finished-early path: a goroutine
// that returns without ever parking fails the wait with DoneMsg, well before
// the timeout.
func TestAwaitRunFailsWithDoneMsg(t *testing.T) {
	tb := runAwait(t, func() Await {
		done := make(chan struct{})
		go close(done)
		return Await{
			Frame: "parkwait.readUnderLock", Reasons: []string{RWMutexRLock},
			Done: done, DoneMsg: "returned without waiting", Timeout: 10 * time.Second,
		}
	})
	if !tb.failed || tb.msg != "returned without waiting" {
		t.Fatalf("failed=%v msg=%q, want the DoneMsg", tb.failed, tb.msg)
	}
}

// TestAwaitRunDefaultsAnEmptyDoneMsg checks that an Await without DoneMsg
// still fails with a message naming the frame instead of a blank one.
func TestAwaitRunDefaultsAnEmptyDoneMsg(t *testing.T) {
	tb := runAwait(t, func() Await {
		done := make(chan struct{})
		go close(done)
		return Await{Frame: "parkwait.readUnderLock", Reasons: []string{RWMutexRLock}, Done: done}
	})
	if want := "goroutine finished before parking in parkwait.readUnderLock"; !tb.failed || tb.msg != want {
		t.Fatalf("failed=%v msg=%q, want %q", tb.failed, tb.msg, want)
	}
}

// TestAwaitRunReturnsForAParkedGoroutine is the positive case through the
// fake: Run returns without failing once the reader parks.
func TestAwaitRunReturnsForAParkedGoroutine(t *testing.T) {
	var mu sync.RWMutex
	mu.Lock()
	done := make(chan struct{})
	tb := runAwait(t, func() Await {
		go func() {
			defer close(done)
			readUnderLock(&mu)
		}()
		return Await{
			Frame: "parkwait.readUnderLock", Reasons: []string{RWMutexRLock, Semacquire},
			Done: done, Timeout: 10 * time.Second,
		}
	})
	mu.Unlock()
	<-done
	if tb.failed {
		t.Fatalf("Run failed with %q although the reader parked", tb.msg)
	}
}

// TestCountIgnoresGoroutinesStartedElsewhere pins the creator filter: a reader
// parked in the frame but started by another goroutine (as a goroutine leaked
// by another test would be) is not counted, and a wait for it times out.
func TestCountIgnoresGoroutinesStartedElsewhere(t *testing.T) {
	const frame = "parkwait.readUnderLock"
	var mu sync.RWMutex
	mu.Lock()
	done := make(chan struct{})
	creator := make(chan string, 1)
	go func() { // this intermediate goroutine is the reader's creator
		creator <- createdBySuffix()
		go func() {
			defer close(done)
			readUnderLock(&mu)
		}()
	}()
	defer func() { mu.Unlock(); <-done }()

	// Wait until the reader is parked, filtering by its real creator, so the
	// assertions below are not passed vacuously by a reader not yet parked.
	elsewhere := <-creator
	deadline := time.Now().Add(10 * time.Second)
	for countCreatedBy(elsewhere, frame, []string{RWMutexRLock, Semacquire}) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("reader never parked on the read lock")
		}
		time.Sleep(time.Millisecond)
	}
	if n := Count(frame, RWMutexRLock, Semacquire); n != 0 {
		t.Fatalf("Count = %d for a reader started by another goroutine, want 0", n)
	}
	tb := runAwait(t, func() Await {
		return Await{Frame: frame, Reasons: []string{RWMutexRLock, Semacquire}, Timeout: 50 * time.Millisecond}
	})
	if !tb.failed {
		t.Fatal("Run was satisfied by a goroutine another goroutine started")
	}
	// The failure must not claim nothing was parked there: it names the
	// creator filter and how many parked goroutines it excluded.
	want := "1 goroutine(s) parked in parkwait.readUnderLock were started by other goroutines and are ignored"
	if !strings.Contains(tb.msg, want) {
		t.Fatalf("failure %q does not contain %q", tb.msg, want)
	}
}

// fakeDump mirrors a real runtime.Stack(all=true) dump (go1.21+ format, with
// GODEBUG=tracebackancestors ancestor sections), one goroutine per block.
// Every block but goroutine 1 is parked with sync.RWMutex.RLock.
const fakeDump = `goroutine 1 [sync.RWMutex.RLock]:
main.target()
	/src/main.go:5 +0x10

goroutine 40 [sync.RWMutex.RLock]:
sync.(*RWMutex).RLock(...)
	/go/src/sync/rwmutex.go:74
main.target(0xc000010000)
	/src/main.go:11 +0x30
created by main.spawn in goroutine 35
	/src/main.go:16 +0x46

goroutine 41 [sync.RWMutex.RLock]:
sync.(*RWMutex).RLock(...)
	/go/src/sync/rwmutex.go:74
main.target(0xc000010000)
	/src/main.go:11 +0x30
created by main.spawn in goroutine 350
	/src/main.go:16 +0x46

goroutine 42 [sync.RWMutex.RLock]:
sync.(*RWMutex).RLock(...)
	/go/src/sync/rwmutex.go:74
main.other(0xc000010000)
	/src/main.go:21 +0x30
created by main.target in goroutine 35
	/src/main.go:12 +0x46

goroutine 43 [sync.RWMutex.RLock]:
sync.(*RWMutex).RLock(...)
	/go/src/sync/rwmutex.go:74
main.other(0xc000010000)
	/src/main.go:21 +0x30
created by main.spawn in goroutine 35
	/src/main.go:16 +0x46
[originating from goroutine 35]:
main.target(...)
	/src/main.go:12 +0x46
created by main.spawn
	/src/main.go:16 +0x65

goroutine 44 [chan receive]:
main.target(0xc000010000)
	/src/main.go:11 +0x30
created by main.spawn in goroutine 35
	/src/main.go:16 +0x46
`

// TestCountParkedMatchesOwnStackAndExactCreator pins the parsing on a fake
// dump: goroutine 40 is the only one of goroutine 35's parked in main.target
// on the right reason. 41 was created by goroutine 350, which must not pass
// for 35 (it is counted as started elsewhere instead). 42 and 43 only mention
// main.target in their "created by" line or an ancestor stack, not where they
// are parked; 44 has the wrong wait reason; 1 has no creator at all.
func TestCountParkedMatchesOwnStackAndExactCreator(t *testing.T) {
	mine, others := countParked([]byte(fakeDump), " in goroutine 35", "main.target", []string{RWMutexRLock})
	if mine != 1 || others != 1 {
		t.Fatalf("countParked = (mine %d, others %d), want (1, 1)", mine, others)
	}
	mine, others = countParked([]byte(fakeDump), " in goroutine 350", "main.target", []string{RWMutexRLock})
	if mine != 1 || others != 1 {
		t.Fatalf("countParked for creator 350 = (mine %d, others %d), want (1, 1)", mine, others)
	}
}

// TestTimeoutMsgWithoutIgnoredGoroutines checks the message when nothing
// parked in the frame at all: it says so and mentions no ignored goroutines.
func TestTimeoutMsgWithoutIgnoredGoroutines(t *testing.T) {
	a := Await{Frame: "pkg.f", Reasons: []string{MutexLock}, Baseline: 2, TimeoutMsg: "stuck"}
	want := "stuck (no goroutine started by the calling goroutine parked in pkg.f with reason [sync.Mutex.Lock] beyond the baseline 2 after 1s)"
	if got := a.timeoutMsg(time.Second, 0); got != want {
		t.Fatalf("timeoutMsg = %q, want %q", got, want)
	}
}
