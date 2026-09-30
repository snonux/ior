package internal

import (
	"sync"
	"testing"
	"time"
)

// TestReleaseConcurrentlyRunsAllReleasesAtOnce guards task zr2: the sched/task
// probe releases each wait for an RCU grace period, so they must overlap. Every
// release blocks until all of them have started; run serially the first would
// never see the others and would time out.
func TestReleaseConcurrentlyRunsAllReleasesAtOnce(t *testing.T) {
	const n = 3
	var started sync.WaitGroup
	started.Add(n)
	allStarted := make(chan struct{})
	go func() { started.Wait(); close(allStarted) }()

	var mu sync.Mutex
	finished := 0
	timedOut := false
	release := func() {
		started.Done()
		select {
		case <-allStarted:
		case <-time.After(time.Second):
			mu.Lock()
			timedOut = true
			mu.Unlock()
		}
		mu.Lock()
		finished++
		mu.Unlock()
	}

	releaseConcurrently(release, release, release)()

	mu.Lock()
	defer mu.Unlock()
	if timedOut {
		t.Fatal("releases did not run concurrently")
	}
	if finished != n {
		t.Fatalf("returned with %d of %d releases finished; it must wait for all", finished, n)
	}
}

// TestReleaseConcurrentlyWithNoReleases: nothing to do must not block or panic.
func TestReleaseConcurrentlyWithNoReleases(t *testing.T) {
	releaseConcurrently()()
}
