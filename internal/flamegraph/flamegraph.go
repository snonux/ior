package flamegraph

import (
	"context"
	"fmt"
	"ior/internal/event"
	"ior/internal/generated/types"
	"os"
	"path"
	"strings"
)

type counter struct {
	count    uint64
	duration uint64
}

// TODO: Profile for CPU usage
type Flamegraph struct {
	// Collapsed flamegraph stats collector
	collapsed map[string]map[types.TraceId]counter
	inCh      chan *event.Pair
	Done      chan struct{}
}

func New() Flamegraph {
	return Flamegraph{
		collapsed: make(map[string]map[types.TraceId]counter),
		inCh:      make(chan *event.Pair, 4096),
		Done:      make(chan struct{}),
	}
}

func (f Flamegraph) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case ev := <-f.inCh:
				pathname := path.Dir(ev.File.Name())
				pathMap, ok := f.collapsed[pathname]
				if !ok {
					pathMap = make(map[types.TraceId]counter)
				}

				traceId := ev.EnterEv.GetTraceId()
				cnt := pathMap[traceId]
				cnt.count++
				cnt.duration += ev.Duration
				pathMap[traceId] = cnt

				f.collapsed[pathname] = pathMap
				ev.RecyclePrev()
			default:
				select {
				case <-ctx.Done():
					fmt.Println("Flamegraph processed last event")
					f.dump()
					close(f.Done)
					return
				default:
				}
			}
		}
	}()
}

func (f Flamegraph) Add(ev *event.Pair) {
	f.inCh <- ev
}

func (f Flamegraph) dump() {
	f.dumpBy("ior-by-count-flamegraph.collapsed", func(cnt counter) uint64 {
		return cnt.count
	})
	f.dumpBy("ior-by-duration-flamegraph.collapsed", func(cnt counter) uint64 {
		return cnt.duration
	})
}

func (f Flamegraph) dumpBy(outfile string, by func(counter) uint64) {
	fmt.Println("Dumping", outfile)
	file, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for path, value := range f.collapsed {
		var sb strings.Builder

		for i, part := range strings.Split(path, "/") {
			if i > 1 {
				sb.WriteString(";")
				sb.WriteString("/")
			}
			sb.WriteString(part)
		}

		for traceId, cnt := range value {
			_, err := fmt.Fprintf(file, "%s;syscall`%s %v\n", sb.String(), traceId, by(cnt))
			if err != nil {
				panic(err)
			}
		}
	}
}
