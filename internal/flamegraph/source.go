package flamegraph

// This file is the single home of the live-trie contract. Its consumers are
// the flamegraph TUI model (internal/tui/flamegraph: Model holds a
// LiveTrieSource, background refreshes a Snapshotter), the dashboard
// (internal/tui/dashboard, which resets the trie and hands it to the
// flamegraph model) and the runtime wiring contract (internal/runtime, via
// its LiveTrieSource alias in RuntimePublisher.SetLiveTrie). All of them
// already import this leaf package, so declaring the interfaces here keeps
// one definition without an import cycle and without making the TUI widget
// depend on the runtime contract or the runtime contract depend on a TUI
// package.

// Snapshotter is the read-only side of the trie contract: version polling and
// snapshot retrieval. Background refresh jobs hold only this narrower view so
// they cannot mutate trie state.
type Snapshotter interface {
	// Version returns the monotonically-increasing snapshot generation counter.
	// Callers use it to avoid re-rendering an unchanged trie.
	Version() uint64
	// SnapshotTree returns a ready-to-render snapshot tree. The tree is
	// shared between callers and must be treated as read-only.
	SnapshotTree() (*SnapshotNode, uint64)
}

// Configurator is the mutating side of the trie contract: grouping-field
// layout, metric selection and baseline reset.
type Configurator interface {
	// Fields returns the current ordered list of grouping fields (e.g. ["comm","path"]).
	Fields() []string
	// CountField returns the active aggregation metric name (e.g. "count", "bytes").
	CountField() string
	// HeightField returns the active frame-height metric (e.g. "bytes", "duration").
	HeightField() string
	// Reconfigure replaces the grouping fields and resets accumulated data so a
	// new baseline begins with the new field order.
	Reconfigure([]string) error
	// SetCountField changes the active aggregation metric and starts a fresh baseline.
	SetCountField(string) error
	// SetHeightField changes the frame-height metric and starts a fresh baseline.
	SetHeightField(string) error
	// Reset clears all accumulated data so the next ingested event starts a new baseline.
	Reset()
}

// LiveTrieSource is the full live-trie contract: the read side (Snapshotter)
// plus the mutating side (Configurator). Consumers that need only one side
// should hold the narrower interface.
type LiveTrieSource interface {
	Snapshotter
	Configurator
}

// *LiveTrie is the production implementation of the whole contract.
var (
	_ Snapshotter    = (*LiveTrie)(nil)
	_ Configurator   = (*LiveTrie)(nil)
	_ LiveTrieSource = (*LiveTrie)(nil)
)
