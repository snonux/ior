package flamegraph

import (
	"testing"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

func ingestTwoEventsForAsync(t *testing.T, trie *coreflamegraph.LiveTrie) {
	t.Helper()
	for i := 0; i < 2; i++ {
		traceID := types.SYS_ENTER_READ
		if i%2 == 0 {
			traceID = types.SYS_ENTER_WRITE
		}
		pair := newBenchmarkPair("worker", traceID, uint32(1000+i), uint32(200000+i), "/srv/app")
		trie.Ingest(pair)
		pair.Recycle()
	}
}

func TestRefreshFromLiveTrieCmdNilWhenNoTrie(t *testing.T) {
	m := NewModel(nil)
	if cmd := m.RefreshFromLiveTrieCmd(); cmd != nil {
		t.Fatalf("expected nil command when liveTrie is nil")
	}
}

func TestRefreshFromLiveTrieCmdProducesSnapshotReady(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	ingestTwoEventsForAsync(t, trie)
	m := NewModel(trie)
	m.width = 120
	m.height = 30

	cmd := m.RefreshFromLiveTrieCmd()
	if cmd == nil {
		t.Fatalf("expected a refresh command when trie has new events")
	}
	if !m.refreshInFlight {
		t.Fatalf("expected refreshInFlight=true after dispatch")
	}

	msg := cmd()
	ready, ok := msg.(flameSnapshotReadyMsg)
	if !ok {
		t.Fatalf("expected flameSnapshotReadyMsg, got %T", msg)
	}
	if ready.snapshot == nil {
		t.Fatalf("expected snapshot in ready message")
	}
	if ready.layoutWidth != 120 || ready.layoutHeight != 30 {
		t.Fatalf("ready msg layout = %dx%d, want 120x30", ready.layoutWidth, ready.layoutHeight)
	}
	if ready.version == 0 {
		t.Fatalf("expected non-zero version after ingestion")
	}
	if len(ready.ancestry.parent) != len(ready.targetFrames) {
		t.Fatalf("ancestry length %d != frames length %d", len(ready.ancestry.parent), len(ready.targetFrames))
	}
}

func TestRefreshFromLiveTrieCmdCoalescesInFlight(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	ingestTwoEventsForAsync(t, trie)
	m := NewModel(trie)
	m.width = 80
	m.height = 24

	if first := m.RefreshFromLiveTrieCmd(); first == nil {
		t.Fatalf("expected first cmd to dispatch")
	}
	if second := m.RefreshFromLiveTrieCmd(); second != nil {
		t.Fatalf("expected second cmd to coalesce (return nil) while a refresh is in flight")
	}
}

func TestRefreshFromLiveTrieCmdSkippedWhileUserDrives(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	ingestTwoEventsForAsync(t, trie)
	m := NewModel(trie)
	m.width = 80
	m.height = 24

	// Load an initial snapshot so the drive gate (which requires an existing
	// snapshot to skip) takes effect.
	if !m.RefreshFromLiveTrie() {
		t.Fatalf("expected initial sync refresh to populate snapshot")
	}
	ingestTwoEventsForAsync(t, trie)

	m.lastKeyAt = time.Now()
	if cmd := m.RefreshFromLiveTrieCmd(); cmd != nil {
		t.Fatalf("expected refresh to be skipped while user is actively pressing keys")
	}

	// Move the timestamp outside the drive window — should dispatch.
	m.lastKeyAt = time.Now().Add(-2 * driveWindow)
	if cmd := m.RefreshFromLiveTrieCmd(); cmd == nil {
		t.Fatalf("expected refresh to dispatch once drive window expires")
	}
}

func TestSnapshotReadyHandlerSnapsToTargetWhileDriving(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	ingestTwoEventsForAsync(t, trie)
	m := NewModel(trie)
	m.width = 120
	m.height = 30
	m.refreshInFlight = true

	cmd := func() tea.Cmd {
		liveTrie := trie
		return func() tea.Msg {
			tree, ver := liveTrie.SnapshotTree()
			targetFrames := buildTerminalLayoutWithPath(tree, m.width, m.height, "")
			ancestry := buildFrameAncestry(targetFrames)
			return flameSnapshotReadyMsg{
				version:      ver,
				layoutWidth:  m.width,
				layoutHeight: m.height,
				snapshot:     tree,
				targetFrames: targetFrames,
				ancestry:     ancestry,
				globalTotal:  snapshotTotal(tree),
			}
		}
	}()
	msg := cmd().(flameSnapshotReadyMsg)

	m.lastKeyAt = time.Now()
	next, _ := m.handleSnapshotReady(msg)
	post := next.(Model)
	if post.animating {
		t.Fatalf("expected snapshot ready to skip animation while user is driving")
	}
	if len(post.frames) != len(msg.targetFrames) {
		t.Fatalf("expected frames to snap directly to target (len %d != %d)", len(post.frames), len(msg.targetFrames))
	}
}

func TestViewCacheReusesContentWhenStateUnchanged(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	ingestTwoEventsForAsync(t, trie)
	m := NewModel(trie)
	m.width = 120
	m.height = 30
	if !m.RefreshFromLiveTrie() {
		t.Fatalf("expected initial refresh to populate snapshot")
	}

	// Drain any pending animation so the cache path is exercised.
	for m.animating {
		nextModel, _ := m.Update(animTickMsg{})
		m = nextModel.(Model)
	}

	first := m.View().Content
	if !m.viewCache.valid {
		t.Fatalf("expected viewCache to be marked valid after first View() call")
	}
	cachedAddr := &m.viewCache.content

	second := m.View().Content
	if first != second {
		t.Fatalf("expected identical content from two consecutive View() calls when state unchanged")
	}
	if cachedAddr != &m.viewCache.content {
		t.Fatalf("expected cache content pointer to remain stable on a hit")
	}
}

func BenchmarkRecomputeFilterState(b *testing.B) {
	// Performance target: 5000-frame filter recompute should remain below 200us/op.
	cases := []struct {
		label      string
		frameCount int
	}{
		{label: "1000frames", frameCount: 1000},
		{label: "5000frames", frameCount: 5000},
	}
	queries := []string{"sys_", "read", "/srv"}

	for _, tc := range cases {
		frames := benchmarkFramesForCount(tc.frameCount)
		decorateFramesForSearch(frames)
		b.Run(tc.label, func(b *testing.B) {
			model := NewModel(nil)
			model.frames = frames
			model.ancestry = buildFrameAncestry(frames)
			model.selectedIdx = midDepthFrameIndex(frames)

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				model.applySearchQuery(queries[i%len(queries)])
				benchIntSink = len(model.matchIndices)
			}
		})
	}
}
