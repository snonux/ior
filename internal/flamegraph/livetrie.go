package flamegraph

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"ior/internal/collapse"
	"ior/internal/event"
)

const (
	// liveTrieMinFraction is the share of the running root total below which
	// a subtree is pruned from snapshots.
	liveTrieMinFraction = 0.001
	// liveTrieMinVisibleChildrenWhenPruned is how many of the largest
	// children stay visible when pruning would hide all of them.
	liveTrieMinVisibleChildrenWhenPruned = 8
	// liveTrieVisibleChildrenFallbackMaxDepth is the deepest level (root = 0)
	// at which that fallback applies.
	liveTrieVisibleChildrenFallbackMaxDepth = 1
)

// SnapshotNode is one node of a serialised flamegraph snapshot tree: a frame
// with its own value, its subtree total, an optional height metric and its
// children. The short JSON keys keep snapshot payloads small.
type SnapshotNode struct {
	Name        string          `json:"n"`
	Value       uint64          `json:"v"`
	Total       uint64          `json:"t"`
	HeightTotal uint64          `json:"ht,omitempty"`
	Children    []*SnapshotNode `json:"c,omitempty"`
}

// LiveTrie is a thread-safe trie used for live flamegraph snapshots. It only
// grows until it holds maxNodes nodes; then compactLocked folds the
// lowest-ranked (low-rate) subtrees into "[other;]" buckets
// (liveTrieOtherFrame), so memory stays bounded on long sessions while all
// totals are conserved.
type LiveTrie struct {
	mu   sync.RWMutex
	root *trieNode
	// nodeCount is the number of nodes below the root; maxNodes is the cap
	// that triggers compaction (liveTrieMaxNodes; tests lower it, and a
	// value below 2 disables compaction).
	nodeCount int
	maxNodes  int
	// lastCompactRootTotal is the root total at the previous compaction,
	// which sizes the rate window (see rateClock).
	lastCompactRootTotal uint64
	version              atomic.Uint64
	fields               []string
	countField           string
	heightField          string

	// Tree cache avoids rebuilding the snapshot tree while the version is
	// unchanged. Built lazily; invalidated on reset and on field/metric
	// reconfiguration.
	treeCacheMu sync.Mutex
	treeVersion uint64
	treeCache   *SnapshotNode
}

// NewLiveTrie constructs an empty live trie with the configured frame/count/height fields.
func NewLiveTrie(fields []string, countField, heightField string) *LiveTrie {
	if !isLiveTrieCountField(countField) {
		countField = "count"
	}
	if heightField != "" && !isLiveTrieCountField(heightField) {
		heightField = ""
	}
	return &LiveTrie{
		root: &trieNode{
			childMap: make(map[string]*trieNode),
		},
		maxNodes:    liveTrieMaxNodes,
		fields:      slices.Clone(fields),
		countField:  countField,
		heightField: heightField,
	}
}

func (lt *LiveTrie) addLocked(frames []string, value, heightValue uint64) {
	lt.nodeCount += insertLiveTriePath(lt.root, frames, value, heightValue)
	if lt.maxNodes >= 2 && lt.nodeCount > lt.maxNodes {
		lt.compactLocked()
	}
}

func (lt *LiveTrie) resetLocked() {
	lt.root = &trieNode{
		childMap: make(map[string]*trieNode),
	}
	lt.nodeCount = 0
	lt.lastCompactRootTotal = 0
	lt.version.Add(1)
}

func (lt *LiveTrie) invalidateCache() {
	lt.treeCacheMu.Lock()
	defer lt.treeCacheMu.Unlock()
	lt.treeVersion = 0
	lt.treeCache = nil
}

// Ingest adds one event pair into the live trie.
func (lt *LiveTrie) Ingest(ep *event.Pair) {
	record := eventPairToRecord(ep)
	lt.AddRecord(record)
}

// addRecordConfig returns the current frame fields and metrics. The fields
// slice is returned without a copy: Reconfigure always installs a fresh slice
// and nothing ever writes into an installed one, so the caller can read it
// after the lock is released. That saves an allocation on every event.
func (lt *LiveTrie) addRecordConfig() ([]string, string, string) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	return lt.fields, lt.countField, lt.heightField
}

// AddRecord adds one already-decoded flamegraph record into the live trie.
func (lt *LiveTrie) AddRecord(record IterRecord) {
	for {
		fields, countField, heightField := lt.addRecordConfig()

		value, err := record.Cnt.ValueByName(countField)
		if err != nil {
			return
		}
		heightValue := uint64(0)
		if heightField != "" {
			heightValue, err = record.Cnt.ValueByName(heightField)
			if err != nil {
				return
			}
		}

		frames := buildFrames(record, fields)

		committed := func() bool {
			lt.mu.Lock()
			defer lt.mu.Unlock()
			if countField != lt.countField || heightField != lt.heightField || !slices.Equal(fields, lt.fields) {
				return false
			}
			lt.addLocked(frames, value, heightValue)
			lt.version.Add(1)
			return true
		}()
		if committed {
			return
		}
	}
}

// Reset clears the trie so live snapshots start from a new baseline.
func (lt *LiveTrie) Reset() {
	func() {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		lt.resetLocked()
	}()
	lt.invalidateCache()
}

// Fields returns the currently configured frame fields in stack order.
func (lt *LiveTrie) Fields() []string {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	out := slices.Clone(lt.fields)
	return out
}

// CountField returns the active metric used to aggregate node values.
func (lt *LiveTrie) CountField() string {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	field := lt.countField
	return field
}

// HeightField returns the active metric used to aggregate node heights.
func (lt *LiveTrie) HeightField() string {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	field := lt.heightField
	return field
}

// SetCountField changes the active aggregation metric and starts a new baseline.
func (lt *LiveTrie) SetCountField(countField string) error {
	field := strings.TrimSpace(countField)
	if !isLiveTrieCountField(field) {
		return fmt.Errorf("invalid count field %q", countField)
	}

	changed := false
	func() {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		if lt.countField == field {
			return
		}
		lt.countField = field
		lt.resetLocked()
		changed = true
	}()
	if !changed {
		return nil
	}
	lt.invalidateCache()
	return nil
}

// SetHeightField changes the active height metric and starts a new baseline.
func (lt *LiveTrie) SetHeightField(heightField string) error {
	field := strings.TrimSpace(heightField)
	if field != "" && !isLiveTrieCountField(field) {
		return fmt.Errorf("invalid height field %q", heightField)
	}

	changed := false
	func() {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		if lt.heightField == field {
			return
		}
		lt.heightField = field
		lt.resetLocked()
		changed = true
	}()
	if !changed {
		return nil
	}
	lt.invalidateCache()
	return nil
}

// Reconfigure changes frame fields and clears accumulated data for a new baseline.
func (lt *LiveTrie) Reconfigure(fields []string) error {
	normalized, err := normalizeLiveTrieFields(fields)
	if err != nil {
		return err
	}

	func() {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		lt.fields = slices.Clone(normalized)
		lt.resetLocked()
	}()
	lt.invalidateCache()
	return nil
}

// Version returns the current ingest version of the trie.
func (lt *LiveTrie) Version() uint64 {
	return lt.version.Load()
}

// SnapshotTree returns the live trie snapshot as a typed node tree. The
// pointer is safe to retain — buildSnapshot allocates fresh nodes per
// snapshot, and the trie never mutates a previously returned tree. Building
// holds the read lock, which blocks ingestion, so it only touches the visible
// nodes, reading the incrementally maintained subtree totals (see
// snapshotBuilder). The tree is cached per version and shared between
// callers, so callers must treat it as read-only. The TUI uses this on a
// background goroutine so per-tick refreshes don't block the Bubble Tea
// update loop.
func (lt *LiveTrie) SnapshotTree() (*SnapshotNode, uint64) {
	version := lt.Version()
	tree, ok := func() (*SnapshotNode, bool) {
		lt.treeCacheMu.Lock()
		defer lt.treeCacheMu.Unlock()
		if lt.treeVersion == version && lt.treeCache != nil {
			return lt.treeCache, true
		}
		return nil, false
	}()
	if ok {
		return tree, version
	}

	version, tree = func() (uint64, *SnapshotNode) {
		lt.mu.RLock()
		defer lt.mu.RUnlock()
		currentVersion := lt.version.Load()
		return currentVersion, buildSnapshot(lt.root, 0, liveTrieMinFraction, lt.root.total)
	}()

	lt.treeCacheMu.Lock()
	defer lt.treeCacheMu.Unlock()
	// Only commit if no concurrent caller stored a newer version.
	if version >= lt.treeVersion {
		lt.treeVersion = version
		lt.treeCache = tree
	}
	return tree, version
}

// eventPairToRecord converts a pair into the record the live trie and the
// recording share. The path is ep.FileValue(): a fileless pair has an empty
// path, which buildFrames drops (it then contributes only to the trie's
// total, like any empty name) rather than growing an "N:file" frame (task pq2).
// Note the asymmetry with the recording: the live TUI flame view shows such
// events only as root self value, whereas `ior collapsed -fields path` on the
// saved .ior.zst prints the same empty path as an "[unknown]" frame.
func eventPairToRecord(ep *event.Pair) IterRecord {
	return IterRecord{
		Path:    ep.FileValue(),
		TraceID: ep.EnterEv.GetTraceId(),
		Comm:    strings.TrimSpace(ep.Comm),
		Pid:     ep.EnterEv.GetPid(),
		Tid:     ep.EnterEv.GetTid(),
		Flags:   ep.Flags(),
		Cnt: Counter{
			Count:          1,
			Duration:       ep.Duration,
			DurationToPrev: ep.DurationToPrev,
			Bytes:          ep.Bytes,
		},
	}
}

func normalizeLiveTrieFields(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return nil, fmt.Errorf("fields cannot be empty")
	}

	normalized := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, raw := range fields {
		field := strings.TrimSpace(raw)
		if field == "" {
			return nil, fmt.Errorf("fields cannot contain empty values")
		}
		if !isLiveTrieField(field) {
			return nil, fmt.Errorf("invalid field %q", field)
		}
		if _, exists := seen[field]; exists {
			return nil, fmt.Errorf("duplicate field %q", field)
		}
		seen[field] = struct{}{}
		normalized = append(normalized, field)
	}
	return normalized, nil
}

func isLiveTrieField(field string) bool {
	return collapse.IsValidField(field)
}

func isLiveTrieCountField(field string) bool {
	return collapse.IsValidCountField(field)
}
