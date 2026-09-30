package dashboard

import (
	"fmt"
	"testing"

	common "ior/internal/tui/common"
)

// bubbleTestData returns n bubbles with distinct, well-separated values.
func bubbleTestData(n int, scale uint64) []bubbleDatum {
	data := make([]bubbleDatum, 0, n)
	for i := range n {
		name := fmt.Sprintf("item%d", i)
		data = append(data, bubbleDatum{ID: name, Label: name, Count: scale * uint64(n-i), Bytes: 10, Duration: 10})
	}
	return data
}

// settle ticks chart until it reports no animation and returns the frames it
// took, failing when it never settles (the bug this pins: it used to animate
// forever).
func settle(t *testing.T, chart *bubbleChart) int {
	t.Helper()
	const maxFrames = 30 * 30 // 30s of frames; the wobble lasts ~6s
	for frame := 1; frame <= maxFrames; frame++ {
		if !chart.Tick(0) {
			return frame
		}
	}
	t.Fatalf("bubble chart still animating after %d frames", maxFrames)
	return 0
}

func newSettledChart(t *testing.T, data []bubbleDatum) bubbleChart {
	t.Helper()
	chart := newBubbleChart()
	chart.SetViewport(120, 40)
	if !chart.SetData(data) {
		t.Fatal("first data must start an animation")
	}
	settle(t, &chart)
	return chart
}

func TestBubbleChartSettlesAndStaysPut(t *testing.T) {
	chart := newSettledChart(t, bubbleTestData(8, 100))
	before := make([][3]float64, len(chart.nodes))
	for i, n := range chart.nodes {
		before[i] = [3]float64{n.x, n.y, n.radius}
	}
	for range 5 {
		if chart.Tick(0) {
			t.Fatal("a settled chart must stay settled")
		}
	}
	for i, n := range chart.nodes {
		if got := [3]float64{n.x, n.y, n.radius}; got != before[i] {
			t.Fatalf("node %d moved after settling: %v -> %v", i, before[i], got)
		}
	}
	if chart.driftRemaining != 0 {
		t.Fatalf("driftRemaining = %v after settling", chart.driftRemaining)
	}
}

func TestBubbleChartUnchangedDataDoesNotRestartAnimation(t *testing.T) {
	data := bubbleTestData(8, 100)
	chart := newSettledChart(t, data)
	if chart.SetData(data) {
		t.Fatal("identical data must not restart the animation")
	}
	// Tiny live-counter wobble: below the retarget threshold.
	wobble := bubbleTestData(8, 100)
	wobble[0].Count++
	if chart.SetData(wobble) {
		t.Fatal("a one-event change must not restart the animation")
	}
}

func TestBubbleChartRealChangeResumesAnimation(t *testing.T) {
	chart := newSettledChart(t, bubbleTestData(8, 100))

	if !chart.SetData(bubbleTestData(8, 100)[:5]) {
		t.Fatal("removing bubbles must resume the animation")
	}
	settle(t, &chart)

	changed := bubbleTestData(5, 100)
	changed[4].Count = 5000 // reorders and resizes bubbles
	if !chart.SetData(changed) {
		t.Fatal("a large value change must resume the animation")
	}
	settle(t, &chart)

	chart.SetViewport(90, 30) // resize re-lays-out the bubbles
	if !chart.animating {
		t.Fatal("a resize must resume the animation")
	}
}

// TestBubbleRetargetHysteresisAccumulates: sub-threshold changes keep the old
// anchor, so a slow trend eventually crosses the threshold instead of being
// dropped one tiny step at a time (which would leave the picture stale).
func TestBubbleRetargetHysteresisAccumulates(t *testing.T) {
	chart := newSettledChart(t, bubbleTestData(4, 100))
	anchor := chart.nodes[0].anchorX
	prev := chart.nodes[0]
	target := prev
	target.targetX = anchor + bubbleRetargetEpsilon/2
	node := bubbleNode{anchorX: target.targetX} // as mergeTargetNodes builds it
	if chart.inheritPrevNodeState(&node, prev, target) || node.anchorX != anchor {
		t.Fatalf("half-threshold move retargeted: anchor %v", node.anchorX)
	}
	target.targetX = anchor + bubbleRetargetEpsilon*2
	node = bubbleNode{anchorX: target.targetX}
	if !chart.inheritPrevNodeState(&node, prev, target) {
		t.Fatal("a move beyond the threshold must retarget")
	}
	if node.anchorX != target.targetX {
		t.Fatalf("anchor = %v, want %v", node.anchorX, target.targetX)
	}
}

// TestBubbleTickChainEndsOnceSettled drives the real handler: the chain must
// re-arm while animating and stop by itself, in bounded time, afterwards.
func TestBubbleTickChainEndsOnceSettled(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.syscallsTab.mode = tabVizModeBubbles
	m.syscallsTab.bubble.SetViewport(120, 40)
	if !m.syscallsTab.bubble.SetData(bubbleTestData(8, 100)) {
		t.Fatal("fresh data must animate")
	}
	m.ticks.startBubble()
	gen := m.ticks.bubble.gen

	frames := 0
	for ; frames < 30*30; frames++ {
		_, cmd := m.Update(bubbleTickMsg{generation: gen})
		if cmd == nil {
			break
		}
	}
	if frames == 30*30 {
		t.Fatal("bubble tick chain never ended")
	}
	if frames < 30 {
		t.Fatalf("chain ended after %d frames, before the springs could settle", frames)
	}
	if m.syscallsTab.bubble.animating {
		t.Fatal("chain ended while the chart still animates")
	}
	// New data restarts it through the real refresh path.
	if !m.syscallsTab.bubble.SetData(bubbleTestData(3, 100)) {
		t.Fatal("changed data must report animation so the chain restarts")
	}
}

func TestBubbleRenderIsCachedAndInvalidatedByInputs(t *testing.T) {
	chart := newSettledChart(t, bubbleTestData(6, 100))
	first := chart.Render("Syscalls", 120, 40)
	if !chart.frame.hasView {
		t.Fatal("render must fill the frame cache")
	}
	// Poison the cache: an unchanged chart must return the cached view.
	chart.frame.view = "CACHED"
	if got := chart.Render("Syscalls", 120, 40); got != "CACHED" {
		t.Fatalf("unchanged chart re-rendered: %.40q", got)
	}
	mutations := map[string]func(){
		"node moved":    func() { chart.nodes[0].x += 1 },
		"node resized":  func() { chart.nodes[1].radius += 0.5 },
		"selection":     func() { chart.selected = (chart.selected + 1) % len(chart.nodes) },
		"theme":         func() { chart.isDark = !chart.isDark },
		"status hint":   func() { chart.statusHint = "hint" },
		"selected data": func() { chart.nodes[chart.selected].Bytes++ },
		"metric":        func() { chart.SetMetric(bubbleMetricBytes) },
	}
	for name, mutate := range mutations {
		chart.frame.view = "CACHED"
		mutate()
		if got := chart.Render("Syscalls", 120, 40); got == "CACHED" {
			t.Errorf("%s: served a stale cached view", name)
		}
	}
	chart.frame.view = "CACHED"
	if got := chart.Render("Syscalls", 100, 40); got == "CACHED" {
		t.Error("width change: served a stale cached view")
	}
	chart.frame.view = "CACHED"
	if got := chart.Render("Files", 100, 40); got == "CACHED" {
		t.Error("tab label change: served a stale cached view")
	}
	// The uncached render is deterministic: same inputs, same text.
	chart2 := newSettledChart(t, bubbleTestData(6, 100))
	if again := chart2.Render("Syscalls", 120, 40); again != first {
		t.Error("identical charts rendered differently")
	}
}

// BenchmarkBubbleTickAndView measures one animation frame (Tick + Render) of
// a realistic chart. It was 9.9ms at 120x40 and 46ms at 300x80.
func BenchmarkBubbleTickAndView(b *testing.B) {
	for _, size := range [][2]int{{120, 40}, {300, 80}} {
		b.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(b *testing.B) {
			chart := newBubbleChart()
			chart.SetViewport(size[0], size[1])
			chart.SetData(bubbleTestData(bubbleMaxItems, 100))
			b.ReportAllocs()
			for b.Loop() {
				chart.driftRemaining = bubbleDriftSeconds // keep it moving
				chart.Tick(0)
				_ = chart.Render("Syscalls", size[0], size[1])
			}
		})
	}
}

// BenchmarkBubbleIdleView measures View on a settled chart, which is what
// every key press or unrelated message costs; the frame cache makes it cheap.
func BenchmarkBubbleIdleView(b *testing.B) {
	chart := newBubbleChart()
	chart.SetViewport(300, 80)
	chart.SetData(bubbleTestData(bubbleMaxItems, 100))
	for chart.Tick(0) {
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = chart.Render("Syscalls", 300, 80)
	}
}
