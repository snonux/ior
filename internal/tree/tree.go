package tree

import (
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

// It's a "flat tree" stored in a map, one key per directory
type Tree struct {
	// Collapsed flamegraph stats collector
	collapsed map[string]map[types.TraceId]counter
	inCh      chan *event.Pair
	Finished  chan struct{}
}

func New() Tree {
	return Tree{
		collapsed: make(map[string]map[types.TraceId]counter),
		inCh:      make(chan *event.Pair, 4096),
		Finished:  make(chan struct{}),
	}
}

func (t Tree) Add(ev *event.Pair) {
	t.inCh <- ev
}

func (t Tree) Start() {
	go func() {
		for ev := range t.inCh {
			pathname := path.Dir(ev.File.Name())
			pathMap, ok := t.collapsed[pathname]
			if !ok {
				pathMap = make(map[types.TraceId]counter)
			}

			traceId := ev.EnterEv.GetTraceId()
			cnt := pathMap[traceId]
			cnt.count++
			cnt.duration += ev.Duration
			pathMap[traceId] = cnt

			t.collapsed[pathname] = pathMap
			ev.RecyclePrev()
		}
		fmt.Println("Tree processed last event")
		t.mustDump("ior.collapsed")
		close(t.Finished)
		fmt.Println("DEBUG")
	}()
}

// TODO: By count and by duration
// TODO: Reverse by syscall vs path
// TODO: Allow full path?
func (t Tree) mustDump(outfile string) {
	fmt.Println("Writing", outfile)
	file, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for path, value := range t.collapsed {
		var sb strings.Builder

		for _, part := range strings.Split(path, "/") {
			sb.WriteString("/")
			sb.WriteString(part)
		}

		for traceId, cnt := range value {
			_, err := fmt.Fprintf(file, "%s;%s %v\n", sb.String(), traceId, cnt.count)
			if err != nil {
				panic(err)
			}
		}
	}
}
