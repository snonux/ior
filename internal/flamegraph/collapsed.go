package flamegraph

import (
	"fmt"
	"ior/internal/types"
	"os"
	"strings"
	"sync"
)

type counter struct {
	count    uint64
	duration uint64
}

func (c *counter) merge(other counter) {
	c.count += other.count
	c.duration += other.duration
}

type collapsed map[string]map[types.TraceId]counter

// TODO: Unit test this
func (c collapsed) merge(other collapsed) (merged int) {
	for k, v := range other {
		if _, ok := c[k]; !ok {
			c[k] = make(map[types.TraceId]counter)
		}
		for traceId, cnt := range v {
			if existingCnt, ok := c[k][traceId]; ok {
				existingCnt.merge(cnt)
				merged++
				c[k][traceId] = existingCnt
				continue
			}
			c[k][traceId] = cnt
		}
	}
	return
}

func (c collapsed) dump() {
	var wg sync.WaitGroup
	wg.Add(4)

	go c.dumpBy(&wg, "ior-by-path-count-flamegraph.collapsed", true, func(cnt counter) uint64 {
		return cnt.count
	})
	go c.dumpBy(&wg, "ior-by-path-duration-flamegraph.collapsed", true, func(cnt counter) uint64 {
		return cnt.duration
	})
	go c.dumpBy(&wg, "ior-by-syscall-count-flamegraph.collapsed", false, func(cnt counter) uint64 {
		return cnt.count
	})
	go c.dumpBy(&wg, "ior-by-syscall-duration-flamegraph.collapsed", false, func(cnt counter) uint64 {
		return cnt.duration
	})

	wg.Wait()
}

func (c collapsed) dumpBy(wg *sync.WaitGroup, outfile string, syscallAtTop bool, by func(counter) uint64) {
	defer wg.Done()

	fmt.Println("Dumping", outfile)
	file, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for path, value := range c {
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
