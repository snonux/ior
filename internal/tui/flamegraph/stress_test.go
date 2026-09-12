package flamegraph

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
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
	// allocation counters rather than wall clock, which is what keeps them
	// from measuring the host: across idle runs, -race runs and runs under 8x
	// to 16x CPU oversubscription the pass cost 28917-28958 allocations (a
	// 0.14% spread), while peak wall-clock render latency over the same
	// conditions went 11.6ms, 63.0ms and 249.6ms.
	//
	// The byte total needed more care. It is not naturally load-independent —
	// see measureStressRenderCost, which pins both GC triggers to make it so,
	// and stressByteCeilingPercent for the residual that pinning does not
	// remove. With those pins the non-race measurement holds to 0.45%
	// (1466874-1473450 idle, worst adversarial 1491120), so
	// stressMaxRenderBytes sits ~1.21x above the worst of them; -race scales
	// it up.
	//
	// Both are tight enough to catch a regression that makes the pass
	// meaningfully more expensive. json.Marshal -> MarshalIndent lands at
	// 2572819-2579412 bytes/pass with a two-space indent, and 1989570 with a
	// tab — the latter under the 2400000 ceiling this replaced, so the
	// tightening bought a real catch. Dropping the childStates preallocation
	// in livetrie.go lands at 32560-32561 allocs, under the allocation
	// ceiling, and 1816954-1823520 bytes: on the non-race build the byte
	// ceiling is the only thing that catches it, which is why it must not
	// simply be widened. (Under -race that mutation also inflates the count to
	// 43514, so `mage testRace` catches it either way.)
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

	// Disable GC for the measurement window. encoding/json keeps its
	// encodeState buffers in a sync.Pool, which GC drains; the more often GC
	// runs, the more of those buffers each pass has to allocate afresh. That
	// makes bytes/pass a function of GC frequency - and so of CPU pressure and
	// of -race's memory overhead - which is exactly the host-dependence this
	// test exists to avoid. With the collector off the pass allocates the same
	// bytes every time, so the ceiling gates the code and not the machine.
	//
	// Both pins are needed. SetGCPercent(-1) stops GOGC-triggered and
	// sysmon's periodic forced collections, but GOMEMLIMIT still triggers one
	// regardless, which is reachable in any memory-capped container: under
	// GOGC=1 GOMEMLIMIT=16MiB the pass measured 1699908 bytes with only the
	// GC-percent pin in place, against an 1800000 ceiling.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(math.MaxInt64))

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
	byteCeiling := stressMaxRenderBytes * stressByteCeilingPercent() / 100
	t.Logf("render cost: allocs/pass=%d bytes/pass=%d (ceilings %d / %d)",
		allocs, bytesPerPass, stressMaxRenderAllocs, byteCeiling)
	if allocs > stressMaxRenderAllocs {
		t.Errorf("render pass allocates too much: allocs/pass=%d ceiling=%d", allocs, stressMaxRenderAllocs)
	}
	if bytesPerPass > byteCeiling {
		t.Errorf("render pass allocates too many bytes: bytes/pass=%d ceiling=%d", bytesPerPass, byteCeiling)
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
// two snapshot APIs: the typed tree from SnapshotTree and the tree the JSON
// path yields (SnapshotJSON + decode) lay out to identical frames.
//
// What this does and does not buy, precisely. SnapshotJSON is
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
	decoded, _, err := renderStressFrame(liveTrie)
	if err != nil {
		t.Fatalf("JSON snapshot path failed: %v", err)
	}
	if treeVersion != equivalenceFixtureEvents {
		t.Fatalf("snapshot version = %d, want %d", treeVersion, equivalenceFixtureEvents)
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
	jsonCalls int
}

func (c *countingTrie) SnapshotTree() (*snapshotNode, uint64) {
	c.treeCalls++
	return c.LiveTrie.SnapshotTree()
}

func (c *countingTrie) SnapshotJSON() ([]byte, uint64) {
	c.jsonCalls++
	return c.LiveTrie.SnapshotJSON()
}

// TestFlameRefreshUsesTheTreeSnapshot pins that the flame tab's refresh paths
// take SnapshotTree and never the JSON round-trip.
//
// This is what lets the stress test's cost and frame-count bounds transfer to
// the TUI. Those bounds are measured over the JSON path (see
// renderStressFrame); together with TestSnapshotTreeMatchesJSONRoundTrip, this
// is what stops that from being a measurement of a pipeline the tab does not
// run. It also guards the performance property the tree API exists for: a
// refresh that fell back to SnapshotJSON would marshal and re-parse the whole
// trie on every tick.
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
	if len(model.frames) == 0 {
		t.Fatal("refresh produced no frames")
	}
	if trie.treeCalls == 0 {
		t.Error("RefreshFromLiveTrie never called SnapshotTree")
	}
	if trie.jsonCalls != 0 {
		t.Errorf("RefreshFromLiveTrie took the JSON round-trip: SnapshotJSON calls=%d", trie.jsonCalls)
	}

	// The per-tick refresh the dashboard actually dispatches
	// (dashboard/model.go calls RefreshFromLiveTrieCmd and runs the cmd).
	// Drive it through the cmd, not through buildSnapshotMsg directly: the
	// closure RefreshFromLiveTrieCmd returns is its own call site, and
	// rewriting only that closure to round-trip through JSON is a regression
	// a direct buildSnapshotMsg call cannot see.
	ingestStressEvent(trie.LiveTrie, "worker-0", 1000, equivalenceFixtureEvents)
	beforeTree, beforeJSON := trie.treeCalls, trie.jsonCalls
	cmd := model.RefreshFromLiveTrieCmd()
	if cmd == nil {
		t.Fatal("RefreshFromLiveTrieCmd returned no command for a changed trie")
	}
	ready, ok := cmd().(flameSnapshotReadyMsg)
	if !ok {
		t.Fatalf("refresh cmd produced %T, want flameSnapshotReadyMsg", cmd())
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
	if trie.jsonCalls != beforeJSON {
		t.Errorf("the per-tick refresh cmd took the JSON round-trip: SnapshotJSON calls=%d",
			trie.jsonCalls-beforeJSON)
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
