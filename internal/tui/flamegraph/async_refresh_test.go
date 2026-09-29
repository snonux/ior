package flamegraph

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
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
	if ready.generation != m.refreshGeneration {
		t.Fatalf("ready msg generation = %d, want %d", ready.generation, m.refreshGeneration)
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

func TestSetLiveTrieInvalidatesOldDispatchedCompletionWithoutReleasingNewRefresh(t *testing.T) {
	oldTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(oldTrie, 0)
	m := NewModel(oldTrie)
	m.width = 120
	m.height = 30

	oldCmd := m.RefreshFromLiveTrieCmd()
	if oldCmd == nil {
		t.Fatal("expected old-session refresh command")
	}

	newTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(newTrie, 1)
	m.SetLiveTrie(newTrie)
	if m.refreshInFlight {
		t.Fatal("SetLiveTrie left the old session's in-flight slot occupied")
	}
	newCmd := m.RefreshFromLiveTrieCmd()
	if newCmd == nil {
		t.Fatal("expected new-session refresh command")
	}

	oldReady := oldCmd()
	handled, followup := m.HandleRefreshCompletion(oldReady, true)
	if !handled {
		t.Fatal("old-session completion was not recognized")
	}
	if followup != nil {
		t.Fatal("old-session completion scheduled a command")
	}
	if !m.refreshInFlight {
		t.Fatal("old-session completion released the new session's in-flight slot")
	}
	if got := m.LastVersion(); got != 0 {
		t.Fatalf("old-session completion applied version %d to the new session", got)
	}

	newReady := newCmd()
	handled, _ = m.HandleRefreshCompletion(newReady, true)
	if !handled {
		t.Fatal("new-session completion was not recognized")
	}
	if m.refreshInFlight {
		t.Fatal("new-session completion did not release its in-flight slot")
	}
	if got, want := m.LastVersion(), newTrie.Version(); got != want {
		t.Fatalf("new-session completion applied version %d, want %d", got, want)
	}
}

func TestDiscardedStaleRefreshCompletionReleasesInFlightSlot(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(trie, 0)
	m := NewModel(trie)
	m.width = 120
	m.height = 30
	if !m.RefreshFromLiveTrie() {
		t.Fatal("expected initial refresh to populate a snapshot")
	}
	initialVersion := m.LastVersion()

	coreflamegraph.SeedTestLiveFlameData(trie, 1)
	cmd := m.RefreshFromLiveTrieCmd()
	if cmd == nil {
		t.Fatal("expected background refresh command")
	}
	msg := cmd()
	ready, ok := msg.(flameSnapshotReadyMsg)
	if !ok {
		t.Fatalf("refresh command returned %T, want flameSnapshotReadyMsg", msg)
	}
	// Change only the current viewport field so the completion is stale without
	// starting an unrelated resize animation inside the test.
	m.width = ready.layoutWidth - 1
	if ready.layoutWidth == m.width {
		t.Fatal("test setup did not make the completion stale")
	}

	handled, followup := m.HandleRefreshCompletion(ready, false)
	if !handled {
		t.Fatal("expected stale refresh completion to be recognized")
	}
	if followup != nil {
		t.Fatal("expected discarded stale completion not to schedule a command")
	}
	if m.refreshInFlight {
		t.Fatal("discarded stale completion did not release the in-flight slot")
	}
	if got := m.LastVersion(); got != initialVersion {
		t.Fatalf("discarded stale completion applied version %d, want %d", got, initialVersion)
	}
	if next := m.RefreshFromLiveTrieCmd(); next == nil {
		t.Fatal("expected a later refresh to dispatch after stale completion")
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
	post := next.(*Model)
	if post.anim.animating {
		t.Fatalf("expected snapshot ready to skip animation while user is driving")
	}
	if len(post.anim.frames) != len(msg.targetFrames) {
		t.Fatalf("expected frames to snap directly to target (len %d != %d)", len(post.anim.frames), len(msg.targetFrames))
	}
}

func TestViewCacheReusesContentWhenStateUnchanged(t *testing.T) {
	m := newSettledCachedModel(t)

	first := m.View().Content
	cachedAddr := &m.viewCache.content

	second := m.View().Content
	if first != second {
		t.Fatalf("expected identical content from two consecutive View() calls when state unchanged")
	}
	if cachedAddr != &m.viewCache.content {
		t.Fatalf("expected cache content pointer to remain stable on a hit")
	}
}

// newSettledCachedModel returns a model with a populated snapshot, no pending
// animation and a primed view cache, so the next View() goes through the
// cache path rather than the always-render animation path.
func newSettledCachedModel(t *testing.T) *Model {
	t.Helper()
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	ingestTwoEventsForAsync(t, trie)
	m := NewModel(trie)
	m.width = 120
	m.height = 30
	if !m.RefreshFromLiveTrie() {
		t.Fatalf("expected initial refresh to populate snapshot")
	}
	for m.anim.animating {
		nextModel, _ := m.Update(currentAnimTick(m))
		m = nextModel.(*Model)
	}
	_ = m.View()
	if !m.viewCache.valid {
		t.Fatalf("precondition: expected primed view cache")
	}
	return m
}

// visibleText strips ANSI SGR sequences so assertions see the text a user
// would read; the text input styles the prompt, value and cursor separately.
func visibleText(s string) string {
	return ansiSGR.ReplaceAllString(s, "")
}

var ansiSGR = regexp.MustCompile(`\x1b\[[0-9;:]*m`)

// TestViewShowsLiveSearchInputWhileTyping is the regression test for the
// search prompt staying blank while typing: the view cache key only held the
// committed query, so every keystroke after '/' was served the stale frame.
func TestViewShowsLiveSearchInputWhileTyping(t *testing.T) {
	m := newSettledCachedModel(t)

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: '/', Text: "/"})
	typed := ""
	for _, r := range "xyz" {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
		typed += string(r)
		if got := visibleText(m.View().Content); !strings.Contains(got, "/"+typed) {
			t.Fatalf("after typing %q the view does not show the input:\n%s", typed, got)
		}
	}

	// Backspace must shrink the visible input, not keep serving "/xyz".
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyBackspace})
	got := visibleText(m.View().Content)
	if !strings.Contains(got, "/xy") || strings.Contains(got, "/xyz") {
		t.Fatalf("after backspace expected \"/xy\" without \"/xyz\":\n%s", got)
	}

	// Esc cancels: the typed text must disappear from the view again.
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if got := visibleText(m.View().Content); strings.Contains(got, "/xy") {
		t.Fatalf("after esc the search input is still rendered:\n%s", got)
	}
}

// TestViewCacheKeyTracksSearchCursor checks that moving the cursor without
// changing the value still invalidates the cache, since the rendered footer
// places the cursor differently.
func TestViewCacheKeyTracksSearchCursor(t *testing.T) {
	m := newSettledCachedModel(t)
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: '/', Text: "/"})
	for _, r := range "ab" {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	before := m.currentViewCacheKey()
	beforeView := m.View().Content
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
	after := m.currentViewCacheKey()
	if before == after {
		t.Fatalf("cursor move left the cache key unchanged: %+v", after)
	}
	if after.searchInput != "ab" || after.searchCursor != 1 {
		t.Fatalf("expected key input %q cursor 1, got %q cursor %d", "ab", after.searchInput, after.searchCursor)
	}
	// The key changing is not enough on its own: the rendered view must
	// actually move the cursor instead of serving the cached frame.
	if afterView := m.View().Content; afterView == beforeView {
		t.Fatalf("cursor move did not change the rendered view")
	}
}

// TestViewCacheKeyTracksFieldOrder checks that the field-order preset, shown
// as o:order(...) in the toolbar, invalidates the cache on its own.
func TestViewCacheKeyTracksFieldOrder(t *testing.T) {
	m := newSettledCachedModel(t)
	m.width = 240
	if len(m.fieldPresets) < 2 {
		t.Fatalf("precondition: need at least two field presets, got %d", len(m.fieldPresets))
	}
	beforeLabel := m.currentFieldPresetLabel()
	beforeView := visibleText(m.View().Content)
	m.fieldIndex = (m.fieldIndex + 1) % len(m.fieldPresets)
	afterLabel := m.currentFieldPresetLabel()
	if beforeLabel == afterLabel {
		t.Fatalf("precondition: presets share label %q", afterLabel)
	}
	afterView := visibleText(m.View().Content)
	if !strings.Contains(beforeView, "o:order("+beforeLabel+")") {
		t.Fatalf("precondition: toolbar lacks order %q:\n%s", beforeLabel, beforeView)
	}
	if !strings.Contains(afterView, "o:order("+afterLabel+")") {
		t.Fatalf("field order change served a stale toolbar, want order %q:\n%s", afterLabel, afterView)
	}
}

// TestViewDropsEmptySnapshotPanelAfterReset is the regression test for the
// stale "no visible frames" panel: reset drops the snapshot without changing
// lastVersion, and with an unchanged status message the key used to match.
func TestViewDropsEmptySnapshotPanelAfterReset(t *testing.T) {
	m := NewModel(nil)
	m.width = 120
	m.height = 30
	m.snapshot = &snapshotNode{}
	m.statusMessage = "Baseline reset" // as after an earlier 'r' press
	const panel = "has no visible frames"
	if got := m.View().Content; !strings.Contains(got, panel) {
		t.Fatalf("precondition: expected empty-snapshot panel, got:\n%s", got)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: 'r', Text: "r"})
	if m.snapshot != nil {
		t.Fatalf("precondition: reset should drop the snapshot")
	}
	if got := m.View().Content; strings.Contains(got, panel) {
		t.Fatalf("stale empty-snapshot panel served after reset:\n%s", got)
	}
}

// rejectingTrie is a real LiveTrie whose Reconfigure always fails, to drive
// the field-order error path.
type rejectingTrie struct {
	*coreflamegraph.LiveTrie
}

var _ coreflamegraph.LiveTrieSource = (*rejectingTrie)(nil)

func (rejectingTrie) Reconfigure([]string) error {
	return errors.New("reconfigure rejected")
}

// TestCycleFieldOrderKeepsPresetWhenReconfigureFails pins that a rejected
// Reconfigure leaves fieldIndex (and so the toolbar label) on the preset the
// trie is still using, and does not discard the current snapshot.
func TestCycleFieldOrderKeepsPresetWhenReconfigureFails(t *testing.T) {
	trie := &rejectingTrie{coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")}
	ingestTwoEventsForAsync(t, trie.LiveTrie)
	m := NewModel(trie)
	m.width = 240
	m.height = 30
	if !m.RefreshFromLiveTrie() {
		t.Fatalf("expected initial refresh to populate snapshot")
	}
	beforeIndex := m.fieldIndex
	beforeLabel := m.currentFieldPresetLabel()

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: 'o', Text: "o"})
	if m.fieldIndex != beforeIndex {
		t.Fatalf("fieldIndex advanced to %d despite Reconfigure failing, want %d", m.fieldIndex, beforeIndex)
	}
	if !strings.HasPrefix(m.statusMessage, "Field order error:") {
		t.Fatalf("expected field order error status, got %q", m.statusMessage)
	}
	if m.snapshot == nil {
		t.Fatalf("failed reconfigure must not discard the current snapshot")
	}
	if got := visibleText(m.View().Content); !strings.Contains(got, "o:order("+beforeLabel+")") {
		t.Fatalf("toolbar should keep order %q after failure:\n%s", beforeLabel, got)
	}
	if got := trie.Fields(); !reflect.DeepEqual(got, []string{"comm", "path"}) {
		t.Fatalf("trie fields changed despite rejection: %v", got)
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
			model.anim.frames = frames
			model.anim.ancestry = buildFrameAncestry(frames)
			model.sel.selectedIdx = midDepthFrameIndex(frames)

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				model.applySearchQuery(queries[i%len(queries)])
				benchIntSink = len(model.search.matchIndices)
			}
		})
	}
}
