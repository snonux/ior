package internal

import (
	"context"
	"time"
)

// startPollLoop runs tick every `every` until ctx is cancelled or the returned
// stop function is called. The stop function blocks until the goroutine has
// exited and then performs one final tick, so a periodic collector never loses
// whatever accumulated between the last interval and shutdown.
//
// It is the shared engine behind the event loop's periodic BPF-map collectors
// (aggregateDrainer, ringbufDropMonitor); both differ only in what a tick does.
func startPollLoop(ctx context.Context, every time.Duration, tick func()) func() {
	if tick == nil {
		return func() {}
	}
	if every <= 0 {
		every = defaultAggregateDrainEvery
	}

	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				tick()
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		tick()
	}
}
