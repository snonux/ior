package flamegraph

import (
	"encoding/json"
	"fmt"
	"math"

	"ior/internal/event"
	"ior/internal/file"
	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/types"
)

const (
	fixtureSmallDepth   = 5
	fixtureSmallBreadth = 3

	fixtureMediumDepth   = 10
	fixtureMediumBreadth = 5

	fixtureLargeDepth   = 15
	fixtureLargeBreadth = 8

	fixtureDeepDepth   = 50
	fixtureDeepBreadth = 2

	fixtureWideDepth   = 3
	fixtureWideBreadth = 50
)

func generateTestTrie(depth, breadthPerLevel int) *coreflamegraph.LiveTrie {
	lt := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	comms := []string{"api", "db", "worker", "cache"}
	traceIDs := []types.TraceId{
		types.SYS_ENTER_READ,
		types.SYS_ENTER_WRITE,
		types.SYS_ENTER_OPENAT,
		types.SYS_ENTER_CLOSE,
	}

	totalEvents := maxInt(100, fixtureTargetFrames(depth, breadthPerLevel)/2)
	for i := 0; i < totalEvents; i++ {
		comm := comms[i%len(comms)]
		traceID := traceIDs[i%len(traceIDs)]
		path := buildBenchmarkPath(depth, breadthPerLevel, i)
		lt.Ingest(newBenchmarkPair(comm, traceID, uint32(1000+(i%256)), uint32(200000+i), path))
	}
	return lt
}

func generateTestSnapshot(depth, breadthPerLevel int) *snapshotNode {
	targetFrames := fixtureTargetFrames(depth, breadthPerLevel)
	if targetFrames < 1 {
		targetFrames = 1
	}

	root := &snapshotNode{Name: "root", Value: 1}
	type qItem struct {
		node  *snapshotNode
		depth int
	}
	queue := []qItem{{node: root, depth: 0}}
	created := 1

	for len(queue) > 0 && created < targetFrames {
		item := queue[0]
		queue = queue[1:]
		if item.depth >= depth {
			continue
		}
		remaining := targetFrames - created
		branchCount := breadthPerLevel
		if branchCount > remaining {
			branchCount = remaining
		}
		for i := 0; i < branchCount; i++ {
			child := &snapshotNode{
				Name:  fmt.Sprintf("d%d-n%d", item.depth+1, created+i),
				Value: 1,
			}
			item.node.Children = append(item.node.Children, child)
			queue = append(queue, qItem{node: child, depth: item.depth + 1})
		}
		created += branchCount
	}

	computeSnapshotTotals(root)
	return root
}

func fixtureTargetFrames(depth, breadth int) int {
	switch {
	case depth == fixtureSmallDepth && breadth == fixtureSmallBreadth:
		return 121
	case depth == fixtureMediumDepth && breadth == fixtureMediumBreadth:
		return 2500
	case depth == fixtureLargeDepth && breadth == fixtureLargeBreadth:
		return 12000
	case depth == fixtureDeepDepth && breadth == fixtureDeepBreadth:
		return 100
	case depth == fixtureWideDepth && breadth == fixtureWideBreadth:
		return 5000
	default:
		return maxInt(1, depth*breadth*10)
	}
}

func computeSnapshotTotals(node *snapshotNode) uint64 {
	if node == nil {
		return 0
	}
	total := node.Value
	for _, child := range node.Children {
		total += computeSnapshotTotals(child)
	}
	node.Total = total
	return total
}

func buildBenchmarkPath(depth, breadth, seed int) string {
	if depth < 1 {
		depth = 1
	}
	if breadth < 1 {
		breadth = 1
	}
	path := "/bench"
	value := seed
	for level := 0; level < depth; level++ {
		slot := value % breadth
		path += fmt.Sprintf("/l%d-b%d", level, slot)
		value = value / breadth
	}
	return path
}

func newBenchmarkPair(comm string, traceID types.TraceId, pid, tid uint32, path string) *event.Pair {
	enter := &types.OpenEvent{
		TraceId: traceID,
		Pid:     pid,
		Tid:     tid,
	}
	exit := &types.RetEvent{
		TraceId: types.SYS_EXIT_OPENAT,
		Pid:     pid,
		Tid:     tid,
	}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(3, path, 0)
	pair.Comm = comm
	pair.Duration = 1
	pair.DurationToPrev = 1
	pair.Bytes = 64
	return pair
}

func snapshotNodeCount(node *snapshotNode) int {
	if node == nil {
		return 0
	}
	total := 1
	for _, child := range node.Children {
		total += snapshotNodeCount(child)
	}
	return total
}

func approxEqualCount(got, want int) bool {
	if got == want {
		return true
	}
	const tolerance = 0.2
	diff := math.Abs(float64(got-want)) / float64(want)
	return diff <= tolerance
}

func decodeTrieSnapshot(lt *coreflamegraph.LiveTrie) (*snapshotNode, error) {
	payload, _ := lt.SnapshotJSON()
	var snap snapshotNode
	if err := json.Unmarshal(payload, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
