package dashboard

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"
)

// manyProcessesSnapshot yields n distinct processes with spread-out syscall
// counts, so the treemap and bubble rankings have real work to do.
func manyProcessesSnapshot(n int) *statsengine.Snapshot {
	rows := make([]statsengine.ProcessSnapshot, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, statsengine.ProcessSnapshot{
			PID:            uint32(1000 + i),
			Comm:           fmt.Sprintf("worker-%d", i),
			Syscalls:       uint64(n-i) * 7,
			RatePerSec:     float64(i) * 1.5,
			Bytes:          uint64(i) * 4096,
			AvgLatencyNs:   float64(i) * 100,
			TotalLatencyNs: uint64(i) * 1000,
		})
	}
	return processesSnapshot(rows...)
}

// BenchmarkHandleStatsTickProcesses measures the UI-thread cost of applying
// a stats snapshot with many process rows while the Processes tab is hidden
// (the Overview is shown) and while it is shown, in each viz mode.
func BenchmarkHandleStatsTickProcesses(b *testing.B) {
	for _, rows := range []int{64, 2048} {
		for _, mode := range []tabVizMode{tabVizModeTable, tabVizModeTreemap, tabVizModeBubbles} {
			for _, tab := range []Tab{TabOverview, TabProcesses} {
				name := fmt.Sprintf("rows=%d/mode=%d/active=%d", rows, mode, tab)
				b.Run(name, func(b *testing.B) {
					m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
					m.width, m.height = 120, 28
					m.setTabVizMode(TabProcesses, mode)
					m.activeTab = tab
					snap := manyProcessesSnapshot(rows)
					m.handleStatsTick(messages.StatsTickMsg{Snap: snap})
					b.ReportAllocs()
					for b.Loop() {
						m.handleStatsTick(messages.StatsTickMsg{Snap: snap})
					}
				})
			}
		}
	}
}

// TestRankersFormatDetailOnlyForSurvivors pins the point of task 9r2: the
// detail text is formatted for the items that survive the top-N cut, never
// for the thousands of rows that are dropped. The describe callbacks count
// their calls, so a regression to formatting every row shows up here rather
// than as a slow tick.
func TestRankersFormatDetailOnlyForSurvivors(t *testing.T) {
	const rows = 500
	snap := manyProcessesSnapshot(rows)

	calls := 0
	items := make([]syscallTreemapItem, 0, rows)
	for i := 0; i < rows; i++ {
		items = append(items, syscallTreemapItem{Key: fmt.Sprint(i), Name: fmt.Sprint(i), Value: uint64(rows - i), row: i})
	}
	ranked := rankTreemapItems(items, func(row int) string { calls++; return fmt.Sprint("d", row) })
	if len(ranked) != maxSyscallTreemapItems || calls != maxSyscallTreemapItems {
		t.Fatalf("treemap: %d items, %d describe calls; want %d of each", len(ranked), calls, maxSyscallTreemapItems)
	}
	for i, item := range ranked {
		if item.Detail != fmt.Sprint("d", i) { // Value rank i is source row i
			t.Fatalf("item %d has detail %q, want the detail of its own row", i, item.Detail)
		}
	}

	calls = 0
	data := make([]bubbleDatum, 0, rows)
	for i := 0; i < rows; i++ {
		data = append(data, bubbleDatum{ID: fmt.Sprint(i), Label: fmt.Sprint(i), Count: uint64(rows - i), row: i})
	}
	bubbles := rankBubbleData(data, bubbleMetricCount, func(row int) string { calls++; return fmt.Sprint("d", row) })
	if len(bubbles) != bubbleMaxItems || calls != bubbleMaxItems {
		t.Fatalf("bubbles: %d data, %d describe calls; want %d of each", len(bubbles), calls, bubbleMaxItems)
	}

	// The real builders keep the text users see: the top process is the
	// one with the most syscalls, PID 1000.
	top := buildProcessesTreemapItems(snap, bubbleMetricCount)[0]
	if !strings.HasPrefix(top.Detail, "pid 1000, rate 0.0/s, avg ") {
		t.Fatalf("top treemap detail = %q", top.Detail)
	}
	if got := processBubbleData(snap, bubbleMetricCount)[0].Detail; got != top.Detail {
		t.Fatalf("top bubble detail = %q, want %q", got, top.Detail)
	}
}

// TestHiddenTabNotInBubblesModeIsNotFed checks that a stats tick feeds only
// the bubble charts whose tab is in bubbles mode, and that entering bubbles
// mode fills the chart at once from the latest snapshot.
func TestHiddenTabNotInBubblesModeIsNotFed(t *testing.T) {
	snap := manyProcessesSnapshot(40)
	m := newVizModel(t, TabOverview, tabVizModeTable, snap)
	if m.processesTab.bubble.HasNodes() {
		t.Fatal("a Processes tab in table mode must not have its bubbles fed on a hidden tick")
	}

	m.setTabVizMode(TabProcesses, tabVizModeBubbles)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: snap})
	if !m.processesTab.bubble.HasNodes() {
		t.Fatal("a hidden Processes tab left in bubbles mode must still be fed")
	}

	// Enter bubbles mode from the tab itself: the switch feeds the chart.
	m = newVizModel(t, TabProcesses, tabVizModeTable, snap)
	if m.processesTab.bubble.HasNodes() {
		t.Fatal("table mode must not feed the bubbles, even on the active tab")
	}
	m.cycleVisualizationMode()
	if m.processesTab.mode != tabVizModeBubbles || !m.processesTab.bubble.HasNodes() {
		t.Fatalf("mode %v, nodes %v: cycling into bubbles must fill the chart from the latest snapshot",
			m.processesTab.mode, m.processesTab.bubble.HasNodes())
	}
}
