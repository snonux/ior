package flamegraph

import (
	"context"
	"sync"

	"ior/internal/event"
)

type worker struct {
	iod  iorData
	done chan struct{}
}

func newWorker() worker {
	return worker{iod: newIorData()}
}

func (w worker) run(ctx context.Context, wg *sync.WaitGroup, ch <-chan *event.Pair) {
	defer wg.Done()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			w.iod.addEventPair(ev)
			ev.Recycle()
		case <-ctx.Done():
			return
		}
	}
}
