package flamegraph

import (
	"context"
	"ior/internal/event"
	"ior/internal/types"
	"sync"
	"time"
)

type worker struct {
	collapsed collapsed
	done      chan struct{}
}

func newWorker() worker {
	return worker{collapsed: make(collapsed)}
}

// Run until ch is closed or has no more events and ctx is done.
func (w worker) run(ctx context.Context, wg *sync.WaitGroup, ch <-chan *event.Pair) {
	defer wg.Done()

	for {
		select {
		case ev := <-ch:
			filePath := ev.File.Name()
			pathMap, ok := w.collapsed[filePath]
			if !ok {
				pathMap = make(map[types.TraceId]counter)
			}

			traceId := ev.EnterEv.GetTraceId()
			cnt := pathMap[traceId]
			cnt.count++
			cnt.duration += ev.Duration
			pathMap[traceId] = cnt

			w.collapsed[filePath] = pathMap
			// TODO: Enable Go race detector
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
