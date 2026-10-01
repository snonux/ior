package parkwait

import (
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
