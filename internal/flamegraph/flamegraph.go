package flamegraph

import (
	"context"
	"fmt"
	"ior/internal/event"
	"runtime"
	"sync"
)

// TODO: Add Command in path! Make it configurable? comm/syscall/path, or path/syscall/comm, etc...
// TODO: Idea, show time spent between the syscalls (off syscalls) as well, but in a different color
type Flamegraph struct {
	Ch      chan *event.Pair
	Done    chan struct{}
	workers []worker
}

func New() Flamegraph {
	f := Flamegraph{
		Ch:   make(chan *event.Pair, 4096),
		Done: make(chan struct{}),
	}
	for range runtime.NumCPU() / 2 {
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
			go worker.run(ctx, &wg, f.Ch)
		}
		wg.Wait()

		collapsed := f.workers[0].collapsed
		if len(f.workers) > 1 {
			for i, c := range f.workers[1:] {
				fmt.Println("Worker", i+1, "merged", collapsed.merge(c.collapsed),
					"counters =>", len(collapsed), "total counters")
			}
		}
		collapsed.dump()
	}()
}
