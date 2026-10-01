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
	for _, want := range []string{"never parked (", "no goroutine parked in parkwait.waitOnChannel", "after 20ms"} {
		if !strings.Contains(tb.msg, want) {
			t.Errorf("failure %q does not contain %q", tb.msg, want)
		}
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
}
