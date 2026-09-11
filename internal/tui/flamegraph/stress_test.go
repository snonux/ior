package flamegraph

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

const (
	stressWorkerCount     = 10
	stressEventsPerWorker = 10000
	stressTotalEvents     = stressWorkerCount * stressEventsPerWorker
	stressViewWidth       = 120
	stressViewHeight      = 40
	stressRenderFPS       = 30
	stressFrameBudget     = time.Second / stressRenderFPS

	// Ceilings for one full render pass over the trie this test builds —
	// snapshot rebuild, JSON round-trip and terminal layout. Both are
	// allocation counters rather than wall clock, so a busy host does not
	// move them: across idle runs, -race runs and runs under 8x CPU
	// oversubscription the pass cost 28923-28934 allocations (a 0.04%
	// spread) and 1487146-1572729 bytes, while peak wall-clock render
	// latency over the same three conditions went 11.6ms, 63.0ms and
	// 249.6ms.
	//
	// The ceilings sit ~1.15x above the highest measurement. That is loose
	// enough not to flake — the allocation count barely moves at all, and the
	// byte total's 5.8% spread comes from allocation *sizes* (map and slice
	// growth steps), not from load — and tight enough to catch a regression
	// that makes the pass meaningfully more expensive: swapping
	// json.Marshal for MarshalIndent lands at 2620274 bytes/pass.
	stressMaxRenderAllocs = 33000
	stressMaxRenderBytes  = 1800000
	stressCostSamples     = 20

	// stressExpectedFrames is how many frames the completed fixture trie lays
	// out. See the assertion in TestStressHighEventRate for why it is exact.
	stressExpectedFrames = 321
)

// stressRenderStats accumulates what the concurrent render loop observed while
// the ingest workers were still writing into the trie.
type stressRenderStats struct {
	err         error
	samples     int
	maxFrames   int
	lastFrames  int
	lastTotal   uint64
	total       time.Duration
	maxDuration time.Duration
}

// TestStressHighEventRate renders the flamegraph at the live refresh cadence
// while ten goroutines ingest 100k events into the same trie, and asserts on
// properties that do not depend on how much CPU the host has left: no event is
// lost or double-counted, every intermediate snapshot decodes and lays out
// inside the viewport, snapshot totals never go backwards, and one render pass
// costs a bounded number of allocations. The wall-clock frame budget is
// measured and logged on every run but only *asserted* under IOR_STRESS_TEST=1
// — asserting it by default made this test fail whenever the machine was
// loaded, and -failfast then took the rest of the suite down with it.
func TestStressHighEventRate(t *testing.T) {
	// Deliberately not t.Parallel: the render-cost phase reads process-wide
	// allocation counters, which only attribute to this test while no other
	// test in the package is running.
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")

	ingestDone := make(chan struct{})
	renderDone := make(chan stressRenderStats, 1)
	go func() { renderDone <- runStressRenderLoop(liveTrie, ingestDone) }()

	var ingestWG sync.WaitGroup
	for worker := 0; worker < stressWorkerCount; worker++ {
		worker := worker
		ingestWG.Add(1)
		go func() {
			defer ingestWG.Done()
			for i := 0; i < stressEventsPerWorker; i++ {
				ingestStressEvent(liveTrie, fmt.Sprintf("worker-%d", worker),
					uint32(1000+worker), worker*stressEventsPerWorker+i)
			}
		}()
	}
	ingestWG.Wait()
	close(ingestDone)
	stats := <-renderDone

	if stats.err != nil {
		t.Fatalf("render loop failed: %v", stats.err)
	}
	if stats.samples == 0 {
		t.Fatal("render loop produced no samples")
	}
	// The final sample renders the completed trie, so its frame count is a
	// property of the fixture rather than of the host: 321 idle, under -race
	// and under 8x oversubscription alike. maxFrames is not, and must not be
	// asserted on - pruning is relative to the running root total, so an early
	// snapshot legitimately keeps more nodes, and how many depends on where
	// the render loop's ticks happen to fall (330 and 523 on two runs of the
	// same fixture). It is logged, not checked.
	//
	// Asserting the last sample exactly is what gives this test any grip on
	// pruning at all. The bound it replaced - maxFrames against the viewport's
	// cell count - could not fail: allocateChildWidths never over-allocates a
	// span, and frameBoundsError would catch a violation first. With only that
	// bound, raising liveTrieMinFraction from 0.001 to 0.05 dropped the
	// flamegraph from 321 frames to 21 - most of it gone - and the whole suite
	// still passed.
	//
	// If a fixture or pruning change moves this legitimately, read the new
	// number off the failure and update it deliberately.
	if stats.lastFrames != stressExpectedFrames {
		t.Errorf("completed trie laid out %d frames, want %d: pruning or the fixture changed",
			stats.lastFrames, stressExpectedFrames)
	}
	if stats.lastTotal != stressTotalEvents {
		t.Fatalf("concurrent ingest lost or duplicated events: snapshot total=%d want=%d", stats.lastTotal, stressTotalEvents)
	}
	if version := liveTrie.Version(); version != stressTotalEvents {
		t.Fatalf("trie version = %d, want %d", version, stressTotalEvents)
	}

	avg := stats.total / time.Duration(stats.samples)
	allowedBudget := stressFrameBudget * time.Duration(stressBudgetMultiplier())
	t.Logf("render latency: avg=%s max=%s samples=%d frames=%d peakFrames=%d budget=%s",
		avg, stats.maxDuration, stats.samples, stats.lastFrames, stats.maxFrames, allowedBudget)
	assertStressFrameBudget(t, avg, stats.maxDuration, allowedBudget)

	measureStressRenderCost(t, liveTrie)
}

// runStressRenderLoop renders at the live refresh cadence until ingestDone is
// closed, then renders once more so the final trie is covered too. It checks
// the per-sample invariants itself because they must hold for every
// intermediate snapshot, not only the last one.
func runStressRenderLoop(liveTrie *coreflamegraph.LiveTrie, ingestDone <-chan struct{}) stressRenderStats {
	ticker := time.NewTicker(stressFrameBudget)
	defer ticker.Stop()

	stats := stressRenderStats{}
	for {
		if stats.err = renderStressSample(liveTrie, &stats); stats.err != nil {
			return stats
		}
		select {
		case <-ingestDone:
			// One last pass over the completed trie.
			stats.err = renderStressSample(liveTrie, &stats)
			return stats
		case <-ticker.C:
		}
	}
}

// renderStressSample runs one render pass and folds it into stats, failing on
// any snapshot that cannot be decoded, lays out beyond the viewport, or
// reports a total outside the append-only range the trie guarantees.
func renderStressSample(liveTrie *coreflamegraph.LiveTrie, stats *stressRenderStats) error {
	start := time.Now()
	snapshot, frames, err := renderStressFrame(liveTrie)
	elapsed := time.Since(start)
	if err != nil {
		return err
	}
	if err := frameBoundsError(frames, stressViewWidth, stressViewHeight); err != nil {
		return err
	}
	if snapshot.Total < stats.lastTotal {
		return fmt.Errorf("snapshot total went backwards on an append-only trie: got=%d previous=%d",
			snapshot.Total, stats.lastTotal)
	}
	if snapshot.Total > stressTotalEvents {
		return fmt.Errorf("snapshot total exceeds the ingested events: got=%d max=%d",
			snapshot.Total, stressTotalEvents)
	}
	stats.lastTotal = snapshot.Total
	stats.samples++
	stats.total += elapsed
	if elapsed > stats.maxDuration {
		stats.maxDuration = elapsed
	}
	stats.lastFrames = len(frames)
	if len(frames) > stats.maxFrames {
		stats.maxFrames = len(frames)
	}
	return nil
}

// renderStressFrame runs the JSON snapshot pipeline — SnapshotJSON, decode,
// BuildTerminalLayout — end to end.
//
// This is the path external consumers take, not the one the flame tab takes:
// the tab calls SnapshotTree() and skips the marshal/unmarshal round-trip.
// Both start from the same buildSnapshot output, and
// TestSnapshotTreeMatchesJSONRoundTrip pins that the two produce identical
// layouts, so the cost and pruning bounds measured here carry over to the tab.
// The JSON form is used here because the round-trip also exercises the
// SnapshotNode JSON tags, and because decoding is what catches a snapshot torn
// by a concurrent ingest.
func renderStressFrame(liveTrie *coreflamegraph.LiveTrie) (*snapshotNode, []tuiFrame, error) {
	payload, _ := liveTrie.SnapshotJSON()
	var snapshot snapshotNode
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snapshot, BuildTerminalLayout(&snapshot, stressViewWidth, stressViewHeight), nil
}

// measureStressRenderCost bounds the cost of one render pass in allocations
// instead of nanoseconds. Each pass ingests one more event first so the trie
// version moves and SnapshotJSON cannot serve its cache — that is what the
// live refresh does while events are streaming in.
func measureStressRenderCost(t *testing.T, liveTrie *coreflamegraph.LiveTrie) {
	t.Helper()

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < stressCostSamples; i++ {
		ingestStressEvent(liveTrie, "worker-0", 1000, stressTotalEvents+i)
		_, frames, err := renderStressFrame(liveTrie)
		if err != nil {
			t.Fatalf("render cost sample %d failed: %v", i, err)
		}
		if len(frames) == 0 {
			t.Fatalf("render cost sample %d produced no frames", i)
		}
	}
	runtime.ReadMemStats(&after)

	allocs := (after.Mallocs - before.Mallocs) / stressCostSamples
	bytesPerPass := (after.TotalAlloc - before.TotalAlloc) / stressCostSamples
	t.Logf("render cost: allocs/pass=%d bytes/pass=%d (ceilings %d / %d)",
		allocs, bytesPerPass, stressMaxRenderAllocs, stressMaxRenderBytes)
	if allocs > stressMaxRenderAllocs {
		t.Errorf("render pass allocates too much: allocs/pass=%d ceiling=%d", allocs, stressMaxRenderAllocs)
	}
	if bytesPerPass > stressMaxRenderBytes {
		t.Errorf("render pass allocates too many bytes: bytes/pass=%d ceiling=%d", bytesPerPass, stressMaxRenderBytes)
	}
}

// assertStressFrameBudget checks measured render latency against the frame
// budget, but only when IOR_STRESS_TEST=1 asks for it. Wall-clock latency here
// measures the host as much as the code — a contended box showed a 10-11x
// slowdown — so it is a manual benchmarking signal, not a gate.
func assertStressFrameBudget(t *testing.T, avg, maxSample, allowedBudget time.Duration) {
	t.Helper()
	if os.Getenv("IOR_STRESS_TEST") != "1" {
		return
	}
	if avg > allowedBudget {
		t.Errorf("average render latency exceeded frame budget: avg=%s budget=%s", avg, allowedBudget)
	}
	if maxSample > allowedBudget*6 {
		t.Errorf("max render latency too high: max=%s budget=%s", maxSample, allowedBudget)
	}
}

// ingestStressEvent ingests one deterministic event derived from seed, so the
// trie this test builds is a function of its inputs alone and the render cost
// measured over it is reproducible.
func ingestStressEvent(liveTrie *coreflamegraph.LiveTrie, comm string, pid uint32, seed int) {
	traceID := types.SYS_ENTER_READ
	if seed%2 == 0 {
		traceID = types.SYS_ENTER_WRITE
	}
	pair := newBenchmarkPair(comm, traceID, pid, uint32(200000+seed), buildBenchmarkPath(6, 3, seed))
	liveTrie.Ingest(pair)
	pair.Recycle()
}

// TestSnapshotTreeMatchesJSONRoundTrip pins the equivalence the stress test's
// cost and frame-count bounds rely on: the tree the flame tab renders
// (SnapshotTree) and the tree the JSON path yields (SnapshotJSON + decode) lay
// out to the same frames. Without this, a divergence — a field losing its JSON
// tag, say — would leave TestStressHighEventRate measuring a pipeline the TUI
// no longer runs, and it would still pass.
func TestSnapshotTreeMatchesJSONRoundTrip(t *testing.T) {
	t.Parallel()

	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	for i := 0; i < 2000; i++ {
		ingestStressEvent(liveTrie, fmt.Sprintf("worker-%d", i%10), uint32(1000+i%10), i)
	}

	tree, treeVersion := liveTrie.SnapshotTree()
	decoded, _, err := renderStressFrame(liveTrie)
	if err != nil {
		t.Fatalf("JSON snapshot path failed: %v", err)
	}
	if treeVersion != uint64(2000) {
		t.Fatalf("snapshot version = %d, want 2000", treeVersion)
	}

	treeFrames := BuildTerminalLayout(tree, stressViewWidth, stressViewHeight)
	jsonFrames := BuildTerminalLayout(decoded, stressViewWidth, stressViewHeight)
	if len(treeFrames) == 0 {
		t.Fatal("SnapshotTree laid out no frames")
	}
	if len(treeFrames) != len(jsonFrames) {
		t.Fatalf("frame count differs between snapshot paths: tree=%d json=%d",
			len(treeFrames), len(jsonFrames))
	}
	for i := range treeFrames {
		if treeFrames[i] != jsonFrames[i] {
			t.Fatalf("frame %d differs between snapshot paths:\n tree=%+v\n json=%+v",
				i, treeFrames[i], jsonFrames[i])
		}
	}
	if tree.Total != decoded.Total {
		t.Errorf("root total differs between snapshot paths: tree=%d json=%d", tree.Total, decoded.Total)
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
		model = next.(*Model)
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

	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
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

func settleStressAnimation(model *Model, maxTicks int) *Model {
	for i := 0; i < maxTicks && model.animating; i++ {
		next, _ := model.Update(animTickMsg{})
		model = next.(*Model)
	}
	return model
}

func assertFramesWithinBounds(t *testing.T, frames []tuiFrame, width, height int) {
	t.Helper()
	if err := frameBoundsError(frames, width, height); err != nil {
		t.Fatal(err)
	}
}

// frameBoundsError reports the first frame that falls outside a width x height
// viewport. It returns an error rather than failing a *testing.T so the
// concurrent render loop can check the same invariant from its own goroutine.
func frameBoundsError(frames []tuiFrame, width, height int) error {
	for _, frame := range frames {
		if frame.Col < 0 || frame.Width <= 0 {
			return fmt.Errorf("invalid frame geometry: %+v", frame)
		}
		if frame.Col+frame.Width > width {
			return fmt.Errorf("frame exceeds width %d: %+v", width, frame)
		}
		if frame.Row < 0 || frame.Row >= height {
			return fmt.Errorf("frame row outside height %d: %+v", height, frame)
		}
	}
	return nil
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
