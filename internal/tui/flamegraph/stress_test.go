package flamegraph

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

func TestStressHighEventRate(t *testing.T) {
	t.Parallel()

	const (
		workerCount     = 10
		eventsPerWorker = 10000
		testDuration    = 5 * time.Second
		renderFPS       = 30
		frameBudget     = time.Second / renderFPS
	)
	allowedBudget := frameBudget * time.Duration(stressBudgetMultiplier())

	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	var ingestWG sync.WaitGroup

	type renderMetrics struct {
		err         error
		samples     int
		total       time.Duration
		maxDuration time.Duration
	}
	renderDone := make(chan renderMetrics, 1)

	go func() {
		ticker := time.NewTicker(frameBudget)
		defer ticker.Stop()
		deadline := time.NewTimer(testDuration)
		defer deadline.Stop()

		metrics := renderMetrics{}
		for {
			select {
			case <-ticker.C:
				start := time.Now()
				payload, _ := liveTrie.SnapshotJSON()
				var snapshot snapshotNode
				if err := json.Unmarshal(payload, &snapshot); err != nil {
					metrics.err = fmt.Errorf("decode snapshot: %w", err)
					renderDone <- metrics
					return
				}
				frames := BuildTerminalLayout(&snapshot, 120, 40)
				_ = frames

				elapsed := time.Since(start)
				metrics.samples++
				metrics.total += elapsed
				if elapsed > metrics.maxDuration {
					metrics.maxDuration = elapsed
				}
			case <-deadline.C:
				renderDone <- metrics
				return
			}
		}
	}()

	for worker := 0; worker < workerCount; worker++ {
		worker := worker
		ingestWG.Add(1)
		go func() {
			defer ingestWG.Done()
			for i := 0; i < eventsPerWorker; i++ {
				seed := worker*eventsPerWorker + i
				traceID := types.SYS_ENTER_READ
				if seed%2 == 0 {
					traceID = types.SYS_ENTER_WRITE
				}
				pair := newBenchmarkPair(
					fmt.Sprintf("worker-%d", worker),
					traceID,
					uint32(1000+worker),
					uint32(200000+seed),
					buildBenchmarkPath(6, 3, seed),
				)
				liveTrie.Ingest(pair)
				pair.Recycle()
			}
		}()
	}

	ingestWG.Wait()
	metrics := <-renderDone

	if metrics.err != nil {
		t.Fatalf("render loop failed: %v", metrics.err)
	}
	if metrics.samples == 0 {
		t.Fatal("render loop produced no samples")
	}
	avg := metrics.total / time.Duration(metrics.samples)
	if avg > allowedBudget {
		t.Fatalf("average render latency exceeded frame budget: avg=%s budget=%s samples=%d", avg, allowedBudget, metrics.samples)
	}
	if metrics.maxDuration > allowedBudget*6 {
		t.Fatalf("max render latency too high: max=%s budget=%s", metrics.maxDuration, allowedBudget)
	}
}

func TestStressRapidResize(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.width = 120
	model.height = 40
	model.snapshot = generateTestSnapshot(fixtureMediumDepth, fixtureMediumBreadth)
	model.rebuildFrames(false)
	if len(model.frames) == 0 {
		t.Fatal("expected initial medium fixture frames")
	}

	rng := rand.New(rand.NewSource(42))
	lastWidth, lastHeight := model.width, model.height
	for i := 0; i < 100; i++ {
		lastWidth = 60 + rng.Intn(241) // [60, 300]
		lastHeight = 20 + rng.Intn(61) // [20, 80]
		next, _ := model.Update(tea.WindowSizeMsg{Width: lastWidth, Height: lastHeight})
		model = next.(Model)
		model = settleStressAnimation(model, 180)

		assertFramesWithinBounds(t, model.frames, lastWidth, lastHeight)
		if len(model.frames) > 0 && (model.selectedIdx < 0 || model.selectedIdx >= len(model.frames)) {
			t.Fatalf("invalid selectedIdx after resize %d: idx=%d frames=%d", i, model.selectedIdx, len(model.frames))
		}
	}

	if model.width != lastWidth || model.height != lastHeight {
		t.Fatalf("final viewport mismatch: got %dx%d want %dx%d", model.width, model.height, lastWidth, lastHeight)
	}
	assertFramesWithinBounds(t, model.frames, lastWidth, lastHeight)
}

func TestStressZoomDuringRefresh(t *testing.T) {
	t.Parallel()

	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	ingestStressEvents(liveTrie, 200, 0)

	model := NewModel(liveTrie)
	model.SetViewport(120, 40)
	if changed := model.RefreshFromLiveTrie(); !changed {
		t.Fatal("expected initial live trie refresh")
	}
	if len(model.frames) == 0 {
		t.Fatal("expected initial frames after refresh")
	}

	for i := 0; i < 50; i++ {
		ingestStressEvents(liveTrie, 20, 1000+i*20)
		_ = model.RefreshFromLiveTrie()
		model = settleStressAnimation(model, 180)
		if len(model.frames) == 0 {
			t.Fatalf("expected frames after refresh tick %d", i)
		}

		prevDepth := len(model.zoomStack)
		model.selectedIdx = midDepthFrameIndex(model.frames)
		model.zoomIn()
		model = settleStressAnimation(model, 180)
		if len(model.zoomStack) != prevDepth+1 {
			t.Fatalf("zoom stack did not grow after zoom-in at iteration %d: got=%d want=%d", i, len(model.zoomStack), prevDepth+1)
		}

		model.zoomUndo()
		model = settleStressAnimation(model, 180)
		if len(model.zoomStack) != prevDepth {
			t.Fatalf("zoom stack depth mismatch after undo at iteration %d: got=%d want=%d", i, len(model.zoomStack), prevDepth)
		}
		if model.zoomPath != "" {
			if findNodeByPath(model.snapshot, model.zoomPath) == nil {
				t.Fatalf("zoomPath became invalid after undo at iteration %d: %q", i, model.zoomPath)
			}
		}
		assertFramesWithinBounds(t, model.frames, model.width, model.height)
	}
}

func settleStressAnimation(model Model, maxTicks int) Model {
	for i := 0; i < maxTicks && model.animating; i++ {
		next, _ := model.Update(animTickMsg{})
		model = next.(Model)
	}
	return model
}

func assertFramesWithinBounds(t *testing.T, frames []tuiFrame, width, height int) {
	t.Helper()
	for _, frame := range frames {
		if frame.Col < 0 || frame.Width <= 0 {
			t.Fatalf("invalid frame geometry: %+v", frame)
		}
		if frame.Col+frame.Width > width {
			t.Fatalf("frame exceeds width %d: %+v", width, frame)
		}
		if frame.Row < 0 || frame.Row >= height {
			t.Fatalf("frame row outside height %d: %+v", height, frame)
		}
	}
}

func ingestStressEvents(liveTrie *coreflamegraph.LiveTrie, count, seedBase int) {
	for i := 0; i < count; i++ {
		seed := seedBase + i
		traceID := types.SYS_ENTER_READ
		if seed%3 == 0 {
			traceID = types.SYS_ENTER_OPENAT
		} else if seed%2 == 0 {
			traceID = types.SYS_ENTER_WRITE
		}
		pair := newBenchmarkPair(
			fmt.Sprintf("stress-%d", seed%8),
			traceID,
			uint32(1200+(seed%64)),
			uint32(300000+seed),
			buildBenchmarkPath(9, 5, seed),
		)
		liveTrie.Ingest(pair)
		pair.Recycle()
	}
}
