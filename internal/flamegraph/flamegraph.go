package flamegraph

import (
	"context"
	"fmt"
	"ior/internal/event"
	"ior/internal/generated/types"
	"os"
	"strings"
	"sync"
	"time"
)

type counter struct {
	count    uint64
	duration uint64
}

// TODO: Profile for CPU usage. If too slow, can fan out into multiple maps and
// then merge at the end the maps.
type Flamegraph struct {
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
				// filePath := path.Dir(ev.File.Name())
				filePath := ev.File.Name()
				pathMap, ok := f.collapsed[filePath]
				if !ok {
					pathMap = make(map[types.TraceId]counter)
				}

				traceId := ev.EnterEv.GetTraceId()
				cnt := pathMap[traceId]
				cnt.count++
				cnt.duration += ev.Duration
				pathMap[traceId] = cnt

				f.collapsed[filePath] = pathMap
				ev.RecyclePrev()

			default:
				select {
				case <-ctx.Done():
					defer close(f.Done)
					fmt.Println("Flamegraph processed last event")
					f.dump()
					return
				default:
					time.Sleep(time.Millisecond * 10)
				}
			}
		}
	}()
}

func (f Flamegraph) Add(ev *event.Pair) {
	f.inCh <- ev
}

func (f Flamegraph) dump() {
	var wg sync.WaitGroup
	wg.Add(4)

	go f.dumpBy(&wg, "ior-by-path-count-flamegraph.collapsed", true, func(cnt counter) uint64 {
		return cnt.count
	})
	go f.dumpBy(&wg, "ior-by-path-duration-flamegraph.collapsed", true, func(cnt counter) uint64 {
		return cnt.duration
	})
	go f.dumpBy(&wg, "ior-by-syscall-count-flamegraph.collapsed", false, func(cnt counter) uint64 {
		return cnt.count
	})
	go f.dumpBy(&wg, "ior-by-syscall-duration-flamegraph.collapsed", false, func(cnt counter) uint64 {
		return cnt.duration
	})

	wg.Wait()
}

func (f Flamegraph) dumpBy(wg *sync.WaitGroup, outfile string, syscallAtTop bool, by func(counter) uint64) {
	defer wg.Done()

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
			var err error
			if syscallAtTop {
				_, err = fmt.Fprintf(file, "%s;syscall`%s %v\n", sb.String(), traceId.Name(), by(cnt))
			} else {
				_, err = fmt.Fprintf(file, "syscall`%s;%s %v\n", traceId.Name(), sb.String(), by(cnt))
			}
			if err != nil {
				panic(err)
			}
		}
	}
}
