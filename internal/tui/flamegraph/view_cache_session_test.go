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

// TestViewCacheTracksOrderLabelAcrossSessionSwap pins the refresh generation
// against a stale o:order(...) toolbar label. A session whose trie uses an
// unknown field order gets a custom preset prepended at index 0 - the same
// fieldIndex the previous session used. Both sessions ingest the same three
// records into a six-frame tree, so version, frame count and status message
// also match: only the generation tells the two renders apart. (fieldIndex is
// belt-and-braces in the key: every real path that moves it also advances the
// generation, so it is pinned only by TestViewCacheKeyTracksFieldOrder, which
// moves the index directly.)
func TestViewCacheTracksOrderLabelAcrossSessionSwap(t *testing.T) {
	first := newNamedSessionTrie("same")
	m := NewModel(first)
	m.width, m.height = 120, 30
	loadSession(t, m, first)
	if view := m.View().Content; !strings.Contains(view, "comm/tracepoint/path") {
		t.Fatalf("expected the first session's order in the toolbar:\n%s", view)
	}

	custom := coreflamegraph.NewLiveTrie([]string{"pid", "comm", "path"}, "count", "")
	for _, path := range []string{"/srv/one", "/srv/two", "/srv/three"} {
		custom.AddRecord(coreflamegraph.IterRecord{
			Path: path, TraceID: types.SYS_ENTER_READ, Comm: "same", Pid: 42, Tid: 42,
			Cnt: coreflamegraph.Counter{Count: 10, Duration: 1000, Bytes: 4096},
		})
	}
	if first.Version() != custom.Version() {
		t.Fatalf("test setup: tries must share a version, got %d vs %d", first.Version(), custom.Version())
	}
	frames := len(m.anim.currentFrames())
	loadSession(t, m, custom)
	if got := len(m.anim.currentFrames()); got != frames {
		t.Fatalf("test setup: frame counts must match to collide, %d vs %d", frames, got)
	}
	if m.fieldIndex != 0 {
		t.Fatalf("test setup: custom preset must land at the old index 0, got %d", m.fieldIndex)
	}
	view := m.View().Content
	if !strings.Contains(view, "pid/comm/path") || strings.Contains(view, "comm/tracepoint/path") {
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

// TestViewCacheShowsSearchFooterWhenPromptOpens pins searchActive in the cache
// key. Opening the prompt changes nothing else the key reads (the input is
// still empty, the query unchanged), so without searchActive the cached
// pre-prompt frame would be served and the "0/0 matches" footer would stay
// invisible until the first keystroke. Closing the prompt by Enter (commit,
// input text kept) and by Esc (input cleared) must drop the footer again.
func TestViewCacheShowsSearchFooterWhenPromptOpens(t *testing.T) {
	const footer = "0/0 matches"
	for _, tc := range []struct {
		name  string
		close tea.KeyPressMsg
	}{
		{"enter", tea.KeyPressMsg{Code: tea.KeyEnter}},
		{"escape", tea.KeyPressMsg{Code: tea.KeyEscape}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trie := newNamedSessionTrie("steady")
			m := NewModel(trie)
			m.width, m.height = 120, 30
			loadSession(t, m, trie)
			if view := m.View().Content; strings.Contains(view, footer) {
				t.Fatalf("footer present before the prompt opened:\n%s", view)
			}

			m = deliver(t, m, runeKey('/'))
			if view := m.View().Content; !strings.Contains(view, footer) {
				t.Fatalf("opening the prompt served the cached pre-prompt frame:\n%s", view)
			}
			m = deliver(t, m, tc.close)
			if view := m.View().Content; strings.Contains(view, footer) {
				t.Fatalf("closing the prompt with %s left the footer visible:\n%s", tc.name, view)
			}
		})
	}
}

// TestViewCacheHitDoesNotAllocate checks the cache-hit path with the search
// prompt closed stays allocation-free: building the key is a plain struct of
// scalars and already-held strings, and the compare plus tea.NewView allocate
// nothing. A per-View strings.Join of the order label (the pre-fix behaviour)
// adds an allocation and fails this test. It does not catch an unconditional
// textinput.Value() read: Value() of an empty input does not allocate, so
// that cost only shows with typed text and is covered by the
// searchInput-only-while-open test's behaviour, not by a count here.
func TestViewCacheHitDoesNotAllocate(t *testing.T) {
	trie := newNamedSessionTrie("steady")
	m := NewModel(trie)
	m.width, m.height = 120, 30
	loadSession(t, m, trie)
	_ = m.View() // populate the cache
	if allocs := testing.AllocsPerRun(100, func() { _ = m.View() }); allocs != 0 {
		t.Fatalf("cache-hit View allocated %.0f times per call, want 0", allocs)
	}
}
