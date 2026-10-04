package dashboard

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/statsengine"
)

// The treemap and bubble builders rank first and format Detail afterwards,
// for the survivors only (task 9r2): the ranker hands the builder's describe
// callback the SOURCE ROW index of each survivor, and the callback indexes
// back into the source slice. Nothing but these tests would notice a callback
// that indexed the wrong row (dirs[0] for dirs[row]), because the ranked order
// normally differs from the row order and the wrong detail is still well
// formed text. So the fixtures below are built such that, for each metric, the
// rank order is a different permutation of the row order, with a tie whose
// rows have different detail text, and every survivor's Detail must carry the
// marker of its OWN row.

// rankRow is one fixture row shared by every builder under test.
type rankRow struct {
	name  string // syscall name, directory or comm, unique per row
	count uint64
	bytes uint64
	dur   uint64
}

// rankRows are the fixture rows. Rank order by count is rows 2,1,4,0,3,5 (rows
// 1 and 2 tie and fall back to the name), by bytes 5,2,3,0,4,1 and by duration
// 3,1,4,5,0,2. Row 0 is never the top item, so a detail lookup that always
// reads row 0 is wrong for the first survivor whatever the metric.
var rankRows = []rankRow{
	{"/m0", 5, 3, 2},
	{"/zeta", 9, 1, 7},
	{"/alpha", 9, 8, 1},
	{"/d3", 2, 6, 9},
	{"/e4", 7, 2, 4},
	{"/f5", 1, 9, 3},
}

var rankOrders = map[bubbleMetric][]int{
	bubbleMetricCount:    {2, 1, 4, 0, 3, 5},
	bubbleMetricBytes:    {5, 2, 3, 0, 4, 1},
	bubbleMetricDuration: {3, 1, 4, 5, 0, 2},
}

var rankMetrics = []bubbleMetric{bubbleMetricCount, bubbleMetricBytes, bubbleMetricDuration}

// rankedItem is what every builder yields per survivor, reduced to the
// identity and the detail text.
type rankedItem struct{ key, detail string }

// rankCase is one fixture for one tab: its builders (treemap and bubbles)
// return the survivors in rank order, and keys/markers give, per row, the
// identity and the detail substring that only that row's text contains.
type rankCase struct {
	name    string
	keys    []string
	markers []string
	treemap func(metric bubbleMetric) []rankedItem
	bubbles func(metric bubbleMetric) []rankedItem
}

func treemapPairs(items []syscallTreemapItem) []rankedItem {
	out := make([]rankedItem, 0, len(items))
	for _, it := range items {
		out = append(out, rankedItem{it.Key, it.Detail})
	}
	return out
}

func bubblePairs(data []bubbleDatum) []rankedItem {
	out := make([]rankedItem, 0, len(data))
	for _, d := range data {
		out = append(out, rankedItem{d.ID, d.Detail})
	}
	return out
}

func syscallRankCase() rankCase {
	rows := make([]statsengine.SyscallSnapshot, 0, len(rankRows))
	c := rankCase{name: "syscalls"}
	for i, r := range rankRows {
		name := strings.TrimPrefix(r.name, "/")
		rate, errs := 10+1.5*float64(i), uint64(100+11*i)
		rows = append(rows, statsengine.SyscallSnapshot{
			Name: name, Count: r.count, Bytes: r.bytes, TotalLatencyNs: r.dur,
			RatePerSec: rate, Errors: errs, LatencyP95Ns: uint64(1000 * (i + 1)),
		})
		c.keys = append(c.keys, name)
		c.markers = append(c.markers, fmt.Sprintf("rate %.1f/s, errors %d, p95 %s",
			rate, errs, formatDurationUintNs(uint64(1000*(i+1)))))
	}
	c.treemap = func(m bubbleMetric) []rankedItem { return treemapPairs(buildSyscallTreemapItems(rows, m)) }
	c.bubbles = func(m bubbleMetric) []rankedItem { return bubblePairs(syscallBubbleData(rows, m)) }
	return c
}

// filesRankCase uses the dir-grouped rows: five directories and, as the last
// row, the remainder row the builders append after them.
func filesRankCase() rankCase {
	c := rankCase{name: "dirs"}
	dirs := make([]statsengine.DirSnapshot, 0, len(rankRows))
	var other statsengine.DirSnapshot
	for i, r := range rankRows {
		d := statsengine.DirSnapshot{
			Dir: r.name, Accesses: r.count, BytesRead: r.bytes * 10, BytesWritten: r.bytes,
			TotalLatencyNs: r.dur, FileCount: uint64(20 + 3*i), MaxLatencyNs: uint64(500 * (i + 1)),
		}
		label := d.Dir
		if i == len(rankRows)-1 {
			d.Dir, d.Folded, label = "", 7, "(other: 7 dirs)"
			other = d
		} else {
			dirs = append(dirs, d)
		}
		c.keys = append(c.keys, dirKey(d))
		c.markers = append(c.markers, fmt.Sprintf("dir %s, files %d, read %s, write %s",
			label, d.FileCount, formatBytes(float64(d.BytesRead)), formatBytes(float64(d.BytesWritten))))
	}
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil,
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{}).WithDirs(dirs, other)
	c.treemap = func(m bubbleMetric) []rankedItem { return treemapPairs(buildFilesTreemapItems(&snap, m)) }
	c.bubbles = func(m bubbleMetric) []rankedItem { return bubblePairs(filesDirBubbleData(&snap, m)) }
	return c
}

func processRankCase() rankCase {
	// PIDs ascend with the tie-break order of the names (row 2 before row 1).
	pids := []uint32{5010, 5022, 5021, 5003, 5004, 5005}
	rows := make([]statsengine.ProcessSnapshot, 0, len(rankRows))
	c := rankCase{name: "processes"}
	for i, r := range rankRows {
		rate, avg := 3+0.5*float64(i), float64(100*(i+1))
		p := statsengine.ProcessSnapshot{
			PID: pids[i], Comm: strings.TrimPrefix(r.name, "/"), Syscalls: r.count,
			Bytes: r.bytes, TotalLatencyNs: r.dur, RatePerSec: rate, AvgLatencyNs: avg,
		}
		rows = append(rows, p)
		c.keys = append(c.keys, processRowKey(p))
		c.markers = append(c.markers, fmt.Sprintf("pid %d, rate %.1f/s, avg %s", p.PID, rate, formatDurationNs(avg)))
	}
	snap := processesSnapshot(rows...)
	c.treemap = func(m bubbleMetric) []rankedItem { return treemapPairs(buildProcessesTreemapItems(snap, m)) }
	c.bubbles = func(m bubbleMetric) []rankedItem { return bubblePairs(processBubbleData(snap, m)) }
	return c
}

// TestBuildersDescribeEachSurvivorFromItsOwnRow pins the row-to-detail
// mapping of every real treemap and bubble builder, for every metric.
func TestBuildersDescribeEachSurvivorFromItsOwnRow(t *testing.T) {
	for _, c := range []rankCase{syscallRankCase(), filesRankCase(), processRankCase()} {
		for _, metric := range rankMetrics {
			order := rankOrders[metric]
			for kind, build := range map[string]func(bubbleMetric) []rankedItem{"treemap": c.treemap, "bubbles": c.bubbles} {
				got := build(metric)
				if len(got) != len(order) {
					t.Fatalf("%s %s metric %v: %d survivors, want %d", c.name, kind, metric, len(got), len(order))
				}
				for rank, row := range order {
					if got[rank].key != c.keys[row] {
						t.Fatalf("%s %s metric %v rank %d: key %q, want %q (row %d)",
							c.name, kind, metric, rank, got[rank].key, c.keys[row], row)
					}
					if !strings.Contains(got[rank].detail, c.markers[row]) {
						t.Errorf("%s %s metric %v rank %d (row %d): detail %q lacks its own row's text %q",
							c.name, kind, metric, rank, row, got[rank].detail, c.markers[row])
					}
				}
			}
		}
	}
}
