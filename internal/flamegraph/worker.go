package flamegraph

import (
	"context"
	"ior/internal/event"
	"sync"
	"time"
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
		case ev := <-ch:
			w.iod.add(ev)
			ev.Recycle()

		default:
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(time.Millisecond * 10)
			}
		}
	}
}
