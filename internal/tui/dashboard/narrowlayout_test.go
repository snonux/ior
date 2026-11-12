package dashboard

import (
	"testing"

	"ior/internal/statsengine"
)

// TestIcicleKeepsLargestChildrenWhenTooNarrow pins that a level with more
// nodes than cells draws the largest ones (it used to skip them and draw the
// smallest tail).
func TestIcicleKeepsLargestChildrenWhenTooNarrow(t *testing.T) {
	nodes := []*icicleNode{
		{name: "a", accesses: 1000}, {name: "b", accesses: 900}, {name: "c", accesses: 800},
		{name: "d", accesses: 2}, {name: "e", accesses: 1},
	}
	var tiles []icicleTile
	layoutIcicle(nodes, 0, 2, 0, 1, 0, bubbleMetricCount, &tiles)
	if len(tiles) != 2 || tiles[0].node.name != "a" || tiles[1].node.name != "b" {
		names := make([]string, 0, len(tiles))
		for _, tile := range tiles {
			names = append(names, tile.node.name)
		}
		t.Fatalf("2-cell level drew %v, want [a b]", names)
	}
}

// TestTreemapKeepsLargestItemsWhenTooSmall pins the same for the treemap: a
// strip with fewer cells than items gives its cells to the leading (largest)
// items, one tile each.
func TestTreemapKeepsLargestItemsWhenTooSmall(t *testing.T) {
	items := make([]syscallTreemapItem, 0, 6)
	for i := range 6 {
		items = append(items, syscallTreemapItem{Key: string(rune('a' + i)), Value: uint64(100 - i)})
	}
	tiles := layoutSyscallTreemap(items, 0, 0, 1, 3)
	if len(tiles) != 3 {
		t.Fatalf("1x3 strip drew %d tiles, want 3", len(tiles))
	}
	for i, tile := range tiles {
		if tile.index != i || tile.w < 1 || tile.h < 1 {
			t.Fatalf("tile %d = %+v, want item %d with a cell", i, tile, i)
		}
	}
}

// TestBubbleNodesCarryDuration pins that the live nodes keep the duration the
// status line prints and SetViewport re-lays the chart from.
func TestBubbleNodesCarryDuration(t *testing.T) {
	var chart bubbleChart
	nodes, _ := chart.mergeTargetNodes([]bubbleNode{{ID: "read", Duration: 42}}, nil)
	if len(nodes) != 1 || nodes[0].Duration != 42 {
		t.Fatalf("merged nodes = %+v, want Duration 42", nodes)
	}
}

// TestTreemapGivesEveryItemATileWhenCellsSuffice pins that a skewed value
// distribution cannot leave an item without a tile while the chart has at
// least as many cells as items: the selection walks every item, so a
// tile-less one showed no highlight at all.
func TestTreemapGivesEveryItemATileWhenCellsSuffice(t *testing.T) {
	items := []syscallTreemapItem{{Key: "big", Value: 1_000_000}}
	for i := range 19 {
		items = append(items, syscallTreemapItem{Key: string(rune('a' + i)), Value: uint64(20 - i)})
	}
	for _, size := range [][2]int{{20, 1}, {5, 4}, {4, 5}, {7, 3}, {40, 4}, {3, 7}} {
		tiles := layoutSyscallTreemap(items, 0, 0, size[0], size[1])
		seen := make(map[int]bool, len(tiles))
		cells := 0
		for _, tile := range tiles {
			if tile.w < 1 || tile.h < 1 {
				t.Fatalf("%dx%d: tile %+v has no cell", size[0], size[1], tile)
			}
			seen[tile.index] = true
			cells += tile.w * tile.h
		}
		if len(seen) != len(items) || cells != size[0]*size[1] {
			t.Fatalf("%dx%d: %d of %d items have a tile, covering %d cells", size[0], size[1], len(seen), len(items), cells)
		}
	}
}

// TestProcessSortCacheSortsOncePerSnapshot pins that the sorted Processes
// rows are reused for the same snapshot rows and sort state, and re-sorted
// when either changes.
func TestProcessSortCacheSortsOncePerSnapshot(t *testing.T) {
	rows := []statsengine.ProcessSnapshot{{PID: 3}, {PID: 1}, {PID: 2}}
	byPID := tableSortState[processSortKey]{active: true, key: processSortKeyPID}
	var cache processSortCache
	first := cache.rows(rows, byPID)
	if first[0].PID != 1 || first[2].PID != 3 {
		t.Fatalf("sorted rows = %+v", first)
	}
	if again := cache.rows(rows, byPID); &again[0] != &first[0] {
		t.Fatal("same rows and sort were sorted again")
	}
	reversed := byPID
	reversed.reverse = true
	if got := cache.rows(rows, reversed); got[0].PID != 3 {
		t.Fatalf("changed sort state reused the old order: %+v", got)
	}
	next := []statsengine.ProcessSnapshot{{PID: 9}, {PID: 8}, {PID: 7}}
	if got := cache.rows(next, reversed); got[0].PID != 9 || len(got) != 3 {
		t.Fatalf("new snapshot rows reused the old order: %+v", got)
	}
	if got := cache.rows(rows, tableSortState[processSortKey]{}); &got[0] != &rows[0] {
		t.Fatal("inactive sort must return the rows as they are")
	}
}
