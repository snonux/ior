package flamegraph

import (
	"context"
	"fmt"
	"ior/internal/event"
	"ior/internal/flags"
	"log"
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

func New() Flamegraph {
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
			go worker.run(ctx, &wg, f.Ch)
		}
		wg.Wait()

		iod := f.workers[0].iod
		if len(f.workers) > 1 {
			for i, w := range f.workers[1:] {
				iod = iod.merge(w.iod)
				fmt.Println("Worker", i+1, "merged")
			}
		}
		if err := iod.commit(); err != nil {
			log.Fatal(err)
		}
	}()
}
