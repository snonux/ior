package flamegraph

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/types"
)

// newNamedSessionTrie builds a live trie whose processes are all called comm.
// Every trie built here ingests the same number of records with the same
// weights, so two of them share a snapshot version, frame count and (empty)
// status message and differ only in the frame names - exactly the collision
// the view cache key must survive across a SetLiveTrie session swap.
func newNamedSessionTrie(comm string) *coreflamegraph.LiveTrie {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count", "")
	for _, path := range []string{"/srv/one", "/srv/two", "/srv/three"} {
		trie.AddRecord(coreflamegraph.IterRecord{
			Path:    path,
			TraceID: types.SYS_ENTER_READ,
			Comm:    comm,
			Pid:     42,
			Tid:     42,
			Cnt:     coreflamegraph.Counter{Count: 10, Duration: 1000, Bytes: 4096},
		})
	}
	return trie
}

// loadSession renders the model once against trie so the view cache holds that
// session's frames, like the TUI does between two ticks.
func loadSession(t *testing.T, m *Model, trie *coreflamegraph.LiveTrie) {
	t.Helper()
	m.SetLiveTrie(trie)
	if !m.RefreshFromLiveTrie() {
		t.Fatal("expected the session trie to load a snapshot")
	}
}

// TestViewCacheDoesNotServePreviousSessionFrames proves the suspected stale
// cache hit: after SetLiveTrie swaps in a trie that lands on the same version,
// frame count and status message as the previous session, View must show the
// new session's frame names even though no View ran between the swap and the
// first refresh of the new trie.
func TestViewCacheDoesNotServePreviousSessionFrames(t *testing.T) {
	oldTrie := newNamedSessionTrie("oldsession")
	newTrie := newNamedSessionTrie("newsession")
	if oldTrie.Version() != newTrie.Version() {
		t.Fatalf("test setup: tries must share a version, got %d vs %d", oldTrie.Version(), newTrie.Version())
	}

	m := NewModel(oldTrie)
	m.width, m.height = 120, 30
	loadSession(t, m, oldTrie)
	oldView := m.View().Content
	if !strings.Contains(oldView, "oldsession") {
		t.Fatalf("old session view lacks its frame name:\n%s", oldView)
	}
	oldKeyFrames := len(m.anim.currentFrames())

	// No View between the swap and the refresh: the dashboard attaches a trie
	// and performs the one-off initial load inside a single Update.
	loadSession(t, m, newTrie)
	if got := len(m.anim.currentFrames()); got != oldKeyFrames {
		t.Fatalf("test setup: frame counts must match to collide, %d vs %d", oldKeyFrames, got)
	}

	view := m.View().Content
	if strings.Contains(view, "oldsession") {
		t.Fatalf("view served the previous session's cached frames:\n%s", view)
	}
	if !strings.Contains(view, "newsession") {
		t.Fatalf("view lacks the new session's frame names:\n%s", view)
	}
}

// TestViewCacheStillHitsWithinOneSession is the negative companion: the fix
// must not turn the cache off. Two consecutive Views of an unchanged session
// return the identical memoized string and keep the cache entry valid.
func TestViewCacheStillHitsWithinOneSession(t *testing.T) {
	trie := newNamedSessionTrie("steady")
	m := NewModel(trie)
	m.width, m.height = 120, 30
	loadSession(t, m, trie)

	first := m.View().Content
	if !m.viewCache.valid {
		t.Fatal("expected the first View to populate the cache")
	}
	keyBefore := m.viewCache.key
	second := m.View().Content
	if first != second {
		t.Fatal("unchanged state must render identically")
	}
	if m.viewCache.key != keyBefore {
		t.Fatal("a cache hit must not rewrite the key")
	}
}

// TestViewCacheTracksOrderLabelAcrossSessionSwap guards the key's replacement of
// the joined o:order(...) label by fieldIndex+generation: a session whose trie
// uses an unknown field order gets a custom preset prepended at index 0, the
// same index the previous session used, yet the toolbar label must change.
func TestViewCacheTracksOrderLabelAcrossSessionSwap(t *testing.T) {
	first := newNamedSessionTrie("same")
	m := NewModel(first)
	m.width, m.height = 120, 30
	loadSession(t, m, first)
	if view := m.View().Content; !strings.Contains(view, "comm/tracepoint/path") {
		t.Fatalf("expected the first session's order in the toolbar:\n%s", view)
	}

	custom := coreflamegraph.NewLiveTrie([]string{"path", "comm"}, "count", "")
	custom.AddRecord(coreflamegraph.IterRecord{
		Path: "/srv/one", TraceID: types.SYS_ENTER_READ, Comm: "same", Pid: 42, Tid: 42,
		Cnt: coreflamegraph.Counter{Count: 10},
	})
	loadSession(t, m, custom)
	view := m.View().Content
	if !strings.Contains(view, "path/comm") || strings.Contains(view, "comm/tracepoint/path") {
		t.Fatalf("toolbar kept the previous session's order label:\n%s", view)
	}
}

// TestViewCacheShowsSearchInputOnlyWhileOpen covers the key reading the input
// value and cursor only while the prompt is active: typed text must show up on
// every keystroke while open, and vanish when the prompt is cancelled.
func TestViewCacheShowsSearchInputOnlyWhileOpen(t *testing.T) {
	trie := newNamedSessionTrie("steady")
	m := NewModel(trie)
	m.width, m.height = 120, 30
	loadSession(t, m, trie)
	_ = m.View()

	m = deliver(t, m, runeKey('/'))
	m = deliver(t, m, runeKey('z'))
	m = deliver(t, m, runeKey('q'))
	if view := m.View().Content; !strings.Contains(view, "zq") {
		t.Fatalf("typed search text missing from the open prompt:\n%s", view)
	}
	m = deliver(t, m, runeKey('x'))
	if view := m.View().Content; !strings.Contains(view, "zqx") {
		t.Fatalf("next keystroke served from a stale cache entry:\n%s", view)
	}
	m = deliver(t, m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if view := m.View().Content; strings.Contains(view, "zqx") {
		t.Fatalf("cancelled prompt still renders its input:\n%s", view)
	}
}
