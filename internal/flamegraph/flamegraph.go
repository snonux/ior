package flamegraph

import (
	"context"
	"fmt"
	"ior/internal/event"
	"ior/internal/flags"
	"runtime"
	"sync"
)

// TODO: Add Command in path! Make it configurable? comm/syscall/path, or path/syscall/comm, etc...
// TODO: Idea, show time spent between the syscalls (off syscalls) as well, but in a different color
type Flamegraph struct {
	flags   flags.Flags
	Ch      chan *event.Pair
	Done    chan struct{}
	workers []worker
}

func New(flags flags.Flags) Flamegraph {
	f := Flamegraph{
		Ch:   make(chan *event.Pair, 4096),
		Done: make(chan struct{}),
	}
	numWorkers := runtime.NumCPU() / 4
	if numWorkers == 0 {
		numWorkers = 1
	}
	for range numWorkers {
		f.workers = append(f.workers, newWorker())
	}
	return f
}

func (f Flamegraph) Start(ctx context.Context) {
	go func() {
		defer close(f.Done)
		var wg sync.WaitGroup
		wg.Add(len(f.workers))

		for i, worker := range f.workers {
			fmt.Println("Starting flamegraph worker", i)
			if f.flags.FlamegraphName == "" { // Empty string means: old style collapsed
				go worker.runCollapsed(ctx, &wg, f.Ch)
			} else {
				go worker.run(ctx, &wg, f.Ch)
			}
		}
		wg.Wait()

		// COLLAPSED: Will be removed, once migrated to iorData
		if f.flags.FlamegraphName == "" { // Empty string means: old style collapsed
			collapsed := f.workers[0].collapsed
			if len(f.workers) > 1 {
				for i, c := range f.workers[1:] {
					fmt.Println("Worker", i+1, "merged", collapsed.merge(c.collapsed),
						"counters =>", len(collapsed), "total counters")
				}
			}
			collapsed.dump()
		}
	}()
}
