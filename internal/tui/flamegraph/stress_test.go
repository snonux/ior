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

	// Ceilings for one dispatched production refresh over the trie this test
	// builds: SnapshotTree, zoom handling, terminal layout, ancestry
	// construction, total extraction, and application of the ready message.
	// The ingest that advances the trie version happens outside each measured
	// interval. Allocation counters, unlike wall clock, do not measure how much
	// CPU the host has left.
	//
	// With gap-free child-span allocation, the production path measured 26366
	// allocations / 1479201 bytes in an idle non-race run and 26376 / 1480425
	// with GOGC=1, GOMEMLIMIT=16MiB and GOMAXPROCS=128. A full -race run also
	// stayed below the ceilings. They leave about 11-14% headroom over the
	// measured non-race costs.
	//
	// Dropping the childStates preallocation in livetrie.go demonstrates that
	// both dimensions still matter: non-race rises to 30009 allocations and
	// 1829280 bytes, tripping both ceilings.
	stressMaxRenderAllocs = 30000
	stressMaxRenderBytes  = 1650000
	stressCostSamples     = 20

	// stressExpectedFrames is how many frames the completed fixture trie lays
	// out. See the assertion in TestStressHighEventRate for why it is exact.
	stressExpectedFrames = 381
)

// stressRenderStats accumulates what the concurrent render loop observed while
// the ingest workers were still writing into the trie.
type stressRenderStats struct {
	err            error
	samples        int
	partialSamples int
	maxFrames      int
	lastFrames     int
	lastTotal      uint64
	total          time.Duration
	maxDuration    time.Duration
}

// TestStressHighEventRate renders the flamegraph at the live refresh cadence
// while ten goroutines ingest 100k events into the same trie, and asserts on
// properties that do not depend on how much CPU the host has left: no event is
// lost or double-counted, every intermediate snapshot builds and lays out
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
	partialObserved := make(chan struct{}, 1)
	releaseFinalHalf := make(chan struct{})
	renderDone := make(chan stressRenderStats, 1)
	go func() { renderDone <- runStressRenderLoop(liveTrie, ingestDone, partialObserved) }()

	var ingestWG sync.WaitGroup
	var midpointWG sync.WaitGroup
	midpointWG.Add(stressWorkerCount)
	for worker := 0; worker < stressWorkerCount; worker++ {
		worker := worker
		ingestWG.Add(1)
		go func() {
			defer ingestWG.Done()
			for i := 0; i < stressEventsPerWorker; i++ {
				if i == stressEventsPerWorker/2 {
					midpointWG.Done()
					<-releaseFinalHalf
				}
				ingestStressEvent(liveTrie, fmt.Sprintf("worker-%d", worker),
					uint32(1000+worker), worker*stressEventsPerWorker+i)
			}
		}()
	}

	// Hold every worker at its midpoint until the renderer acknowledges a
	// partial snapshot. This makes the concurrent-snapshot coverage
	// deterministic: the token may describe any strict partial snapshot, and
	// if none arrived during the first half, the stable 50k-event trie gives
	// the renderer another chance before the workers may finish. A sample-count
	// or wall-clock delay would put the same host-load flake back into the test
	// through a side door.
	midpointWG.Wait()
	select {
	case <-partialObserved:
		close(releaseFinalHalf)
	case earlyStats := <-renderDone:
		close(releaseFinalHalf)
		ingestWG.Wait()
		if earlyStats.err != nil {
			t.Fatalf("render loop failed before observing a partial snapshot: %v", earlyStats.err)
		}
		t.Fatal("render loop stopped before observing a partial snapshot")
	}
	ingestWG.Wait()
	close(ingestDone)
	stats := <-renderDone

	if stats.err != nil {
		t.Fatalf("render loop failed: %v", stats.err)
	}
	if stats.partialSamples == 0 {
		t.Fatal("render loop observed no partial snapshot during concurrent ingest")
	}
	// The final sample renders the completed trie, so its frame count is a
	// property of the fixture rather than of the host: 381 idle, under -race
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
	// Direct tests pin the pruning boundary and layout partitioning, but this
	// exact count remains a useful end-to-end sentinel across both stages. If a
	// fixture, pruning or layout change moves it legitimately, read the new
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
// closed, then renders once more when the last sample predates the final trie
// version. It checks the per-sample invariants itself because they must hold
// for every intermediate snapshot, not only the last one.
func runStressRenderLoop(
	liveTrie *coreflamegraph.LiveTrie,
	ingestDone <-chan struct{},
	partialObserved chan<- struct{},
) stressRenderStats {
	ticker := time.NewTicker(stressFrameBudget)
	defer ticker.Stop()

	model := NewModel(liveTrie)
	model.SetViewport(stressViewWidth, stressViewHeight)
	stats := stressRenderStats{}
	for {
		if stats.err = renderStressSample(model, &stats, partialObserved); stats.err != nil {
			return stats
		}
		select {
		case <-ingestDone:
			// Take one last pass when the preceding snapshot raced ahead of
			// the final writes. If it already captured the completed trie, no
			// production refresh would be dispatched for the same version.
			if model.LastVersion() != liveTrie.Version() {
				stats.err = renderStressSample(model, &stats, partialObserved)
			}
			return stats
		case <-ticker.C:
		}
	}
}

// renderStressSample runs one render pass and folds it into stats, failing on
// any snapshot that cannot be built, lays out beyond the viewport, or
// reports a total outside the append-only range the trie guarantees.
func renderStressSample(
	model *Model,
	stats *stressRenderStats,
	partialObserved chan<- struct{},
) error {
	start := time.Now()
	snapshot, frames, changed, err := renderStressFrame(model)
	elapsed := time.Since(start)
	if err != nil {
		return err
	}
	if !changed {
		return nil
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
	if snapshot.Total > 0 && snapshot.Total < stressTotalEvents {
		stats.partialSamples++
		select {
		case partialObserved <- struct{}{}:
		default:
		}
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

// renderStressFrame runs and applies the production refresh command end to end:
// SnapshotTree, zoom handling, terminal layout, ancestry construction, total
// extraction, and the ready-message update dispatched by the dashboard.
// A false changed result is the production no-op for an unchanged trie.
func renderStressFrame(model *Model) (*snapshotNode, []tuiFrame, bool, error) {
	sourceVersion := uint64(0)
	if model.liveTrie != nil {
		sourceVersion = model.liveTrie.Version()
	}
	cmd := model.RefreshFromLiveTrieCmd()
	if cmd == nil {
		switch {
		case model.liveTrie == nil:
			return nil, nil, false, fmt.Errorf("refresh source disappeared")
		case model.refreshInFlight:
			return nil, nil, false, fmt.Errorf("refresh remained in flight after applying its result")
		case model.paused && model.snapshot != nil:
			return nil, nil, false, fmt.Errorf("stress model became paused")
		case model.userDriving() && model.snapshot != nil:
			return nil, nil, false, fmt.Errorf("stress model unexpectedly entered the user-driving window")
		case model.snapshot != nil && model.LastVersion() == sourceVersion:
			return nil, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf(
			"refresh command was not dispatched for model version %d and source version %d",
			model.LastVersion(), sourceVersion,
		)
	}
	msg := cmd()
	ready, ok := msg.(flameSnapshotReadyMsg)
	if !ok {
		return nil, nil, false, fmt.Errorf("snapshot job returned %T, want flameSnapshotReadyMsg", msg)
	}
	if ready.snapshot == nil {
		return nil, nil, false, fmt.Errorf("snapshot job returned no snapshot")
	}
	if len(ready.ancestry.parent) != len(ready.targetFrames) {
		return nil, nil, false, fmt.Errorf("snapshot ancestry has %d entries for %d frames",
			len(ready.ancestry.parent), len(ready.targetFrames))
	}
	next, _ := model.Update(ready)
	if next != model {
		return nil, nil, false, fmt.Errorf("snapshot update returned a different model %T", next)
	}
	return ready.snapshot, ready.targetFrames, true, nil
}

// renderStressJSONFrame round-trips the typed snapshot through JSON and lays
// out the decoded tree. Keeping it separate from renderStressFrame makes JSON
// fidelity a correctness check without mistaking its allocation profile for
// the TUI refresh cost.
func renderStressJSONFrame(liveTrie *coreflamegraph.LiveTrie) (*snapshotNode, []tuiFrame, error) {
	tree, _ := liveTrie.SnapshotTree()
	payload, err := json.Marshal(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("encode snapshot: %w", err)
	}
	var snapshot snapshotNode
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snapshot, buildTerminalLayout(&snapshot, stressViewWidth, stressViewHeight), nil
}

// measureStressRenderCost bounds the cost of the dispatched production refresh
// in allocations instead of nanoseconds. Each pass ingests one more event
// before the measurement so the trie version moves, then executes
// RefreshFromLiveTrieCmd and applies its result exactly as the dashboard does.
func measureStressRenderCost(t *testing.T, liveTrie *coreflamegraph.LiveTrie) {
	t.Helper()

	model := NewModel(liveTrie)
	model.SetViewport(stressViewWidth, stressViewHeight)
	if !model.RefreshFromLiveTrie() {
		t.Fatal("render cost setup did not load the baseline snapshot")
	}

	runtime.GC()
	var totalAllocs, totalBytes uint64
	for i := 0; i < stressCostSamples; i++ {
		ingestStressEvent(liveTrie, "worker-0", 1000, stressTotalEvents+i)

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, frames, changed, err := renderStressFrame(model)
		if err != nil {
			t.Fatalf("render cost sample %d failed: %v", i, err)
		}
		if !changed {
			t.Fatalf("render cost sample %d did not dispatch after ingest", i)
		}
		if len(frames) == 0 {
			t.Fatalf("render cost sample %d produced no frames", i)
		}
		runtime.ReadMemStats(&after)
		totalAllocs += after.Mallocs - before.Mallocs
		totalBytes += after.TotalAlloc - before.TotalAlloc
	}

	allocs := totalAllocs / stressCostSamples
	bytesPerPass := totalBytes / stressCostSamples
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

// equivalenceFixtureEvents is how many events the snapshot-path fixtures
// ingest. The trie version is one per ingested event, so the two are pinned
// together.
const equivalenceFixtureEvents = 2000

// TestSnapshotTreeMatchesJSONRoundTrip pins round-trip fidelity between the
// typed tree from SnapshotTree and the same tree after a JSON marshal+decode:
// both lay out to identical frames.
//
// What this does and does not buy, precisely. The payload is
// json.Marshal(SnapshotTree()) and decodes back into the same struct, so
// marshal and unmarshal stay self-consistent under any *rename* of a JSON tag
// — renaming SnapshotNode.HeightTotal's tag, or deleting the tag outright,
// does not fail this test, and it is not meant to. What it catches is a field
// dropping out of serialization altogether (json:"-" on HeightTotal fails it
// at frame 0), which is the divergence that would make the JSON path stop
// representing the typed one.
//
// It is TestFlameRefreshUsesTheTreeSnapshot, not this test, that pins which
// API the TUI actually calls.
func TestSnapshotTreeMatchesJSONRoundTrip(t *testing.T) {
	t.Parallel()

	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	for i := 0; i < equivalenceFixtureEvents; i++ {
		ingestStressEvent(liveTrie, fmt.Sprintf("worker-%d", i%10), uint32(1000+i%10), i)
	}

	tree, treeVersion := liveTrie.SnapshotTree()
	decoded, _, err := renderStressJSONFrame(liveTrie)
	if err != nil {
		t.Fatalf("JSON snapshot path failed: %v", err)
	}
	if treeVersion != equivalenceFixtureEvents {
		t.Fatalf("snapshot version = %d, want %d", treeVersion, equivalenceFixtureEvents)
	}

	treeFrames := buildTerminalLayout(tree, stressViewWidth, stressViewHeight)
	jsonFrames := buildTerminalLayout(decoded, stressViewWidth, stressViewHeight)
	if len(treeFrames) == 0 {
		t.Fatal("SnapshotTree laid out no frames")
	}
	if len(treeFrames) != len(jsonFrames) {
		t.Fatalf("frame count differs between snapshot paths: tree=%d json=%d",
			len(treeFrames), len(jsonFrames))
	}
	// tuiFrame is comparable today (its only non-numeric field, Fill, is a
	// color.RGBA), so == compares every field. If a field ever becomes an
	// interface holding a non-comparable dynamic type this would panic rather
	// than fail; switch to reflect.DeepEqual if that happens.
	for i := range treeFrames {
		if treeFrames[i] != jsonFrames[i] {
			t.Fatalf("frame %d differs between snapshot paths:\n tree=%+v\n json=%+v",
				i, treeFrames[i], jsonFrames[i])
		}
	}
}

// countingTrie records which snapshot API its caller reached for. It embeds a
// real LiveTrie so the snapshots it returns are the real ones and it satisfies
// the whole LiveTrieSource contract without a hand-written stub.
type countingTrie struct {
	*coreflamegraph.LiveTrie
	treeCalls int
}

var _ coreflamegraph.LiveTrieSource = (*countingTrie)(nil)

func (c *countingTrie) SnapshotTree() (*snapshotNode, uint64) {
	c.treeCalls++
	return c.LiveTrie.SnapshotTree()
}

// TestFlameRefreshUsesTheTreeSnapshot pins that the flame tab's refresh paths
// take the cached SnapshotTree.
//
// The stress test measures this production path directly through
// RefreshFromLiveTrieCmd. This spy independently guards that both refresh
// entry points actually reach the trie's snapshot API, so a refresh that
// stopped consulting the trie is caught here. The dashboard-level
// TestFlameTickDispatchesAndAppliesFlamegraphRefresh pins the outer tick
// dispatch that reaches this command.
func TestFlameRefreshUsesTheTreeSnapshot(t *testing.T) {
	t.Parallel()

	trie := &countingTrie{LiveTrie: coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")}
	for i := 0; i < equivalenceFixtureEvents; i++ {
		ingestStressEvent(trie.LiveTrie, fmt.Sprintf("worker-%d", i%10), uint32(1000+i%10), i)
	}

	model := NewModel(trie)
	model.SetViewport(stressViewWidth, stressViewHeight)
	if changed := model.RefreshFromLiveTrie(); !changed {
		t.Fatal("expected the first refresh to apply a snapshot")
	}
	if len(model.anim.frames) == 0 {
		t.Fatal("refresh produced no frames")
	}
	if trie.treeCalls == 0 {
		t.Error("RefreshFromLiveTrie never called SnapshotTree")
	}

	// The per-tick refresh the dashboard actually dispatches
	// (dashboard/model.go calls RefreshFromLiveTrieCmd and runs the cmd).
	// Drive it through the cmd, not through buildSnapshotMsg directly: the
	// closure RefreshFromLiveTrieCmd returns is its own call site, and
	// rewriting only that closure to bypass SnapshotTree is a regression a
	// direct buildSnapshotMsg call cannot see.
	ingestStressEvent(trie.LiveTrie, "worker-0", 1000, equivalenceFixtureEvents)
	beforeTree := trie.treeCalls
	cmd := model.RefreshFromLiveTrieCmd()
	if cmd == nil {
		t.Fatal("RefreshFromLiveTrieCmd returned no command for a changed trie")
	}
	msg := cmd()
	ready, ok := msg.(flameSnapshotReadyMsg)
	if !ok {
		t.Fatalf("refresh cmd produced %T, want flameSnapshotReadyMsg", msg)
	}
	// flameSnapshotReadyMsg is a struct value, so it is never nil once boxed
	// in tea.Msg — assert it carries a real layout instead. Without this the
	// test passes on a refresh that renders nothing.
	if ready.snapshot == nil {
		t.Error("refresh cmd produced a message with no snapshot")
	}
	if len(ready.targetFrames) == 0 {
		t.Error("refresh cmd produced a message with no frames")
	}
	if trie.treeCalls == beforeTree {
		t.Error("the per-tick refresh cmd never called SnapshotTree")
	}
}

func TestStressRapidResize(t *testing.T) {
	t.Parallel()

	model := NewModel(nil)
	model.width = 120
	model.height = 40
	model.snapshot = generateTestSnapshot(fixtureMediumDepth, fixtureMediumBreadth)
	model.rebuildFrames(false)
	if len(model.anim.frames) == 0 {
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

		assertFramesWithinBounds(t, model.anim.frames, lastWidth, lastHeight)
		if len(model.anim.frames) > 0 && (model.sel.selectedIdx < 0 || model.sel.selectedIdx >= len(model.anim.frames)) {
			t.Fatalf("invalid selectedIdx after resize %d: idx=%d frames=%d", i, model.sel.selectedIdx, len(model.anim.frames))
		}
	}

	if model.width != lastWidth || model.height != lastHeight {
		t.Fatalf("final viewport mismatch: got %dx%d want %dx%d", model.width, model.height, lastWidth, lastHeight)
	}
	assertFramesWithinBounds(t, model.anim.frames, lastWidth, lastHeight)
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
	if len(model.anim.frames) == 0 {
		t.Fatal("expected initial frames after refresh")
	}

	for i := 0; i < 50; i++ {
		ingestStressEvents(liveTrie, 20, 1000+i*20)
		_ = model.RefreshFromLiveTrie()
		model = settleStressAnimation(model, 180)
		if len(model.anim.frames) == 0 {
			t.Fatalf("expected frames after refresh tick %d", i)
		}

		prevDepth := len(model.zoom.zoomStack)
		model.sel.selectedIdx = midDepthFrameIndex(model.anim.frames)
		model.zoomIn()
		model = settleStressAnimation(model, 180)
		if len(model.zoom.zoomStack) != prevDepth+1 {
			t.Fatalf("zoom stack did not grow after zoom-in at iteration %d: got=%d want=%d", i, len(model.zoom.zoomStack), prevDepth+1)
		}

		model.zoomUndo()
		model = settleStressAnimation(model, 180)
		if len(model.zoom.zoomStack) != prevDepth {
			t.Fatalf("zoom stack depth mismatch after undo at iteration %d: got=%d want=%d", i, len(model.zoom.zoomStack), prevDepth)
		}
		if model.zoom.zoomPath != "" {
			if findNodeByPath(model.snapshot, model.zoom.zoomPath) == nil {
				t.Fatalf("zoomPath became invalid after undo at iteration %d: %q", i, model.zoom.zoomPath)
			}
		}
		assertFramesWithinBounds(t, model.anim.frames, model.width, model.height)
	}
}

func settleStressAnimation(model *Model, maxTicks int) *Model {
	for i := 0; i < maxTicks && model.anim.animating; i++ {
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
