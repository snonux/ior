package flamegraph

import (
	"encoding/json"
	"fmt"
	"testing"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/types"

	"github.com/charmbracelet/harmonica"
)

var (
	benchFramesSink []tuiFrame
	benchStringSink string
	benchIntSink    int
	benchFloatSink  float64
)

func BenchmarkBuildTerminalLayout(b *testing.B) {
	// Performance target: medium_120col should remain below 500us/op.
	fixtures := []struct {
		label   string
		depth   int
		breadth int
	}{
		{label: "small", depth: fixtureSmallDepth, breadth: fixtureSmallBreadth},
		{label: "medium", depth: fixtureMediumDepth, breadth: fixtureMediumBreadth},
		{label: "large", depth: fixtureLargeDepth, breadth: fixtureLargeBreadth},
		{label: "deep", depth: fixtureDeepDepth, breadth: fixtureDeepBreadth},
		{label: "wide", depth: fixtureWideDepth, breadth: fixtureWideBreadth},
	}
	widths := []int{80, 120, 200, 300}
	const height = 40

	snapshots := make(map[string]*snapshotNode, len(fixtures))
	for _, fixture := range fixtures {
		snapshots[fixture.label] = generateTestSnapshot(fixture.depth, fixture.breadth)
	}

	for _, fixture := range fixtures {
		snapshot := snapshots[fixture.label]
		for _, width := range widths {
			name := fmt.Sprintf("%s_%dcol", fixture.label, width)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchFramesSink = BuildTerminalLayout(snapshot, width, height)
				}
				if len(benchFramesSink) == 0 {
					b.Fatal("layout returned no frames")
				}
			})
		}
	}
}

func BenchmarkRenderFrame(b *testing.B) {
	// Performance target: medium_120x40 should remain below 2ms/op.
	// Allocation target: run with -benchmem and keep render path below 5 allocs/op.
	fixtures := []struct {
		label    string
		snapshot *snapshotNode
	}{
		{label: "medium", snapshot: generateTestSnapshot(fixtureMediumDepth, fixtureMediumBreadth)},
		{label: "large", snapshot: generateTestSnapshot(fixtureLargeDepth, fixtureLargeBreadth)},
	}
	viewports := []struct {
		width  int
		height int
	}{
		{width: 80, height: 24},
		{width: 120, height: 40},
		{width: 200, height: 60},
	}

	for _, fixture := range fixtures {
		for _, viewport := range viewports {
			name := fmt.Sprintf("%s_%dx%d", fixture.label, viewport.width, viewport.height)
			b.Run(name, func(b *testing.B) {
				model := NewModel(nil)
				model.width = viewport.width
				model.height = viewport.height
				model.snapshot = fixture.snapshot
				model.rebuildFrames(false)
				if len(model.frames) == 0 {
					b.Fatal("render benchmark requires non-empty frame layout")
				}

				for idx := range model.frames {
					switch idx % 12 {
					case 0:
						model.frames[idx].Name = "sys_enter_read"
					case 1:
						model.frames[idx].Name = "sys_enter_write"
					}
				}
				model.selectedIdx = midDepthFrameIndex(model.frames)
				model.subtreeSet = computeSubtreeSetInto(model.frames, model.selectedIdx, model.subtreeSet)
				model.applySearchQuery("sys_")

				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchStringSink = model.View().Content
				}
			})
		}
	}
}

func BenchmarkComputeSubtreeSet(b *testing.B) {
	// Performance target: 1000-frame subtree membership should remain below 100us/op.
	// Allocation target: zero allocs/op by reusing map storage.
	cases := []struct {
		label      string
		frameCount int
	}{
		{label: "100frames", frameCount: 100},
		{label: "1000frames", frameCount: 1000},
		{label: "5000frames", frameCount: 5000},
	}

	for _, tc := range cases {
		frames := benchmarkFramesForCount(tc.frameCount)
		if len(frames) == 0 {
			b.Fatalf("%s produced no frames", tc.label)
		}
		selectedIdx := midDepthFrameIndex(frames)
		reuse := make(map[int]bool, len(frames))

		b.Run(tc.label, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				subtree := computeSubtreeSetInto(frames, selectedIdx, reuse)
				benchIntSink = len(subtree)
			}
		})
	}
}

func BenchmarkSearchHighlight(b *testing.B) {
	// Performance target: 1000-frame search should remain below 200us/op.
	cases := []struct {
		label      string
		frameCount int
	}{
		{label: "100frames", frameCount: 100},
		{label: "1000frames", frameCount: 1000},
		{label: "5000frames", frameCount: 5000},
	}
	queries := []string{"read", "sys_", "/srv/app"}

	for _, tc := range cases {
		frames := benchmarkFramesForCount(tc.frameCount)
		if len(frames) == 0 {
			b.Fatalf("%s produced no frames", tc.label)
		}
		decorateFramesForSearch(frames)

		model := NewModel(nil)
		model.frames = frames
		model.selectedIdx = midDepthFrameIndex(frames)
		model.subtreeSet = computeSubtreeSetInto(model.frames, model.selectedIdx, model.subtreeSet)

		b.Run(tc.label, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				model.applySearchQuery(queries[i%len(queries)])
				benchIntSink = len(model.matchIndices)
			}
		})
	}
}

func BenchmarkSpringUpdate(b *testing.B) {
	// Performance target: 500 active springs should update in < 1ms per tick.
	counts := []int{100, 500, 2000}
	const (
		angularVelocity = 6.0
		damping         = 1.0
	)

	for _, count := range counts {
		b.Run(fmt.Sprintf("%d_springs", count), func(b *testing.B) {
			springs := make([]harmonica.Spring, count)
			current := make([]float64, count)
			velocity := make([]float64, count)
			target := make([]float64, count)

			for idx := range springs {
				springs[idx] = harmonica.NewSpring(harmonica.FPS(30), angularVelocity, damping)
				current[idx] = float64(idx)
				target[idx] = float64(idx + 8)
			}

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for idx := range springs {
					current[idx], velocity[idx] = springs[idx].Update(current[idx], velocity[idx], target[idx])
				}
				benchFloatSink = current[count-1]
			}
		})
	}
}

func BenchmarkAnimationTick(b *testing.B) {
	// Performance target: 500 animated frames should complete in < 1ms per tick.
	// Allocation target: zero allocs/op in the tick + CurrentFrames path.
	counts := []int{100, 500, 2000}

	for _, count := range counts {
		b.Run(fmt.Sprintf("%d_frames", count), func(b *testing.B) {
			state := NewAnimationState(30, 6.0, 1.0)
			base := linearFrames(count, 0, 10)
			target := linearFrames(count, 5, 20)
			state.SetTargets(base)
			state.SetTargets(target)

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !state.Tick(0) {
					for idx := range state.springs {
						state.springs[idx].targetCol += 3
						state.springs[idx].targetW += 2
					}
					state.settled = false
				}
				frames := state.CurrentFrames()
				benchIntSink = frames[len(frames)-1].Width
			}
		})
	}
}

func BenchmarkZoomTransition(b *testing.B) {
	// Performance target: zoom-in transition should stay below 1ms/op.
	snapshot := generateTestSnapshot(fixtureMediumDepth, fixtureMediumBreadth)
	model := NewModel(nil)
	model.width = 120
	model.height = 40
	model.snapshot = snapshot
	model.rebuildFrames(false)
	if len(model.frames) == 0 {
		b.Fatal("zoom benchmark requires non-empty initial layout")
	}
	zoomPath := model.frames[midDepthFrameIndex(model.frames)].Path

	b.Run("zoom_in", func(b *testing.B) {
		benchModel := model
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchModel.zoomReset()
			benchModel.selectedIdx = frameIndexByPath(benchModel.frames, zoomPath)
			benchModel.zoomIn()
			benchIntSink = len(benchModel.targetFrames)
		}
	})

	b.Run("undo_zoom", func(b *testing.B) {
		benchModel := model
		benchModel.selectedIdx = frameIndexByPath(benchModel.frames, zoomPath)
		benchModel.zoomIn()
		if len(benchModel.zoomStack) == 0 {
			b.Fatal("undo benchmark requires an active zoom stack")
		}

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchModel.zoomUndo()
			benchIntSink = len(benchModel.frames)

			benchModel.selectedIdx = frameIndexByPath(benchModel.frames, zoomPath)
			benchModel.zoomIn()
		}
	})
}

func BenchmarkLiveTrieIngestAndSnapshot(b *testing.B) {
	// Performance target: ingest+snapshot pipeline should remain below 200us/op for small/medium cycles.
	counts := []int{100, 1000, 10000}
	for _, count := range counts {
		b.Run(fmt.Sprintf("%d_events", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
				for eventIdx := 0; eventIdx < count; eventIdx++ {
					traceID := types.SYS_ENTER_READ
					if eventIdx%2 == 0 {
						traceID = types.SYS_ENTER_WRITE
					}
					pair := newBenchmarkPair(
						fmt.Sprintf("worker-%d", eventIdx%4),
						traceID,
						uint32(1000+(eventIdx%64)),
						uint32(200000+eventIdx),
						buildBenchmarkPath(8, 6, eventIdx),
					)
					liveTrie.Ingest(pair)
					pair.Recycle()
				}

				payload, _ := liveTrie.SnapshotJSON()
				var snapshot snapshotNode
				if err := json.Unmarshal(payload, &snapshot); err != nil {
					b.Fatalf("snapshot decode failed: %v", err)
				}
				benchFramesSink = BuildTerminalLayout(&snapshot, 120, 40)
			}
		})
	}
}

func BenchmarkResizeRelayout(b *testing.B) {
	// Performance target: resize relayout cost should match BuildTerminalLayout (< 500us medium@120col).
	snapshot := generateTestSnapshot(fixtureMediumDepth, fixtureMediumBreadth)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		frames120 := BuildTerminalLayout(snapshot, 120, 40)
		frames80 := BuildTerminalLayout(snapshot, 80, 24)
		benchFramesSink = BuildTerminalLayout(snapshot, 120, 40)
		benchIntSink = len(frames120) + len(frames80) + len(benchFramesSink)
	}
}

func benchmarkFramesForCount(frameCount int) []tuiFrame {
	var snapshot *snapshotNode
	switch frameCount {
	case 100:
		snapshot = generateTestSnapshot(fixtureDeepDepth, fixtureDeepBreadth)
	case 1000:
		snapshot = generateTestSnapshot(20, 5)
	case 5000:
		snapshot = generateTestSnapshot(fixtureWideDepth, fixtureWideBreadth)
	default:
		snapshot = generateTestSnapshot(10, 5)
	}
	return BuildTerminalLayout(snapshot, 200, 80)
}

func decorateFramesForSearch(frames []tuiFrame) {
	for idx := range frames {
		switch idx % 6 {
		case 0:
			frames[idx].Name = "sys_enter_read"
		case 1:
			frames[idx].Name = "sys_enter_write"
		case 2:
			frames[idx].Name = "read_cache_buffer"
		case 3:
			frames[idx].Name = "path:/srv/app/api"
		case 4:
			frames[idx].Name = "worker_loop"
		default:
			frames[idx].Name = "io_wait"
		}
	}
}

func midDepthFrameIndex(frames []tuiFrame) int {
	if len(frames) == 0 {
		return 0
	}
	maxDepth := 0
	for _, frame := range frames {
		if frame.Depth > maxDepth {
			maxDepth = frame.Depth
		}
	}
	targetDepth := maxDepth / 2
	indices := framesAtDepth(frames, targetDepth)
	if len(indices) == 0 {
		return len(frames) / 2
	}
	return indices[len(indices)/2]
}

func frameIndexByPath(frames []tuiFrame, path string) int {
	for idx, frame := range frames {
		if frame.Path == path {
			return idx
		}
	}
	return 0
}

func linearFrames(count, colOffset, width int) []tuiFrame {
	frames := make([]tuiFrame, count)
	for idx := 0; idx < count; idx++ {
		path := fmt.Sprintf("root%snode-%d", pathSeparator, idx)
		frames[idx] = tuiFrame{
			Name:  fmt.Sprintf("node-%d", idx),
			Path:  path,
			Col:   colOffset + idx,
			Row:   idx % 8,
			Width: width,
		}
	}
	return frames
}
