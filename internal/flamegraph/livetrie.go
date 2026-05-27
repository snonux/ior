package flamegraph

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"ior/internal/collapse"
	"ior/internal/event"
)

const (
	liveTrieMinFraction                     = 0.001
	liveTrieMinVisibleChildrenWhenPruned    = 8
	liveTrieVisibleChildrenFallbackMaxDepth = 1
)

type SnapshotNode struct {
	Name        string          `json:"n"`
	Value       uint64          `json:"v"`
	Total       uint64          `json:"t"`
	HeightTotal uint64          `json:"ht,omitempty"`
	Children    []*SnapshotNode `json:"c,omitempty"`
}

// LiveTrie is a thread-safe, append-only trie used for live flamegraph snapshots.
type LiveTrie struct {
	mu          sync.RWMutex
	root        *trieNode
	maxDepth    int
	version     atomic.Uint64
	fields      []string
	countField  string
	heightField string

	// Snapshot cache avoids recomputing JSON when version is unchanged.
	cacheMu      sync.Mutex
	cacheVersion uint64
	cacheJSON    []byte

	// Tree cache lets the TUI fetch the snapshot tree without a JSON
	// marshal+unmarshal round-trip. Built lazily; invalidated on reset and
	// on field/metric reconfiguration.
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
		fields:      slices.Clone(fields),
		countField:  countField,
		heightField: heightField,
	}
}

func (lt *LiveTrie) addLocked(frames []string, value, heightValue uint64) {
	insertTriePath(lt.root, frames, value, heightValue)
	if len(frames) > lt.maxDepth {
		lt.maxDepth = len(frames)
	}
}

func (lt *LiveTrie) resetLocked() {
	lt.root = &trieNode{
		childMap: make(map[string]*trieNode),
	}
	lt.maxDepth = 0
	lt.version.Add(1)
}

func (lt *LiveTrie) invalidateCache() {
	lt.cacheMu.Lock()
	lt.cacheVersion = 0
	lt.cacheJSON = nil
	lt.cacheMu.Unlock()
	lt.treeCacheMu.Lock()
	lt.treeVersion = 0
	lt.treeCache = nil
	lt.treeCacheMu.Unlock()
}

// Ingest adds one event pair into the live trie.
func (lt *LiveTrie) Ingest(ep *event.Pair) {
	record := eventPairToRecord(ep)
	lt.AddRecord(record)
}

// AddRecord adds one already-decoded flamegraph record into the live trie.
func (lt *LiveTrie) AddRecord(record IterRecord) {
	lt.mu.Lock()

	value, err := record.Cnt.ValueByName(lt.countField)
	if err != nil {
		lt.mu.Unlock()
		return
	}
	heightValue := uint64(0)
	if lt.heightField != "" {
		heightValue, err = record.Cnt.ValueByName(lt.heightField)
		if err != nil {
			lt.mu.Unlock()
			return
		}
	}

	frames := lt.buildFrames(record)
	lt.addLocked(frames, value, heightValue)
	lt.version.Add(1)
	lt.mu.Unlock()
}

// Reset clears the trie so live snapshots start from a new baseline.
func (lt *LiveTrie) Reset() {
	lt.mu.Lock()
	lt.resetLocked()
	lt.mu.Unlock()
	lt.invalidateCache()
}

// Fields returns the currently configured frame fields in stack order.
func (lt *LiveTrie) Fields() []string {
	lt.mu.RLock()
	out := slices.Clone(lt.fields)
	lt.mu.RUnlock()
	return out
}

// CountField returns the active metric used to aggregate node values.
func (lt *LiveTrie) CountField() string {
	lt.mu.RLock()
	field := lt.countField
	lt.mu.RUnlock()
	return field
}

// HeightField returns the active metric used to aggregate node heights.
func (lt *LiveTrie) HeightField() string {
	lt.mu.RLock()
	field := lt.heightField
	lt.mu.RUnlock()
	return field
}

// SetCountField changes the active aggregation metric and starts a new baseline.
func (lt *LiveTrie) SetCountField(countField string) error {
	field := strings.TrimSpace(countField)
	if !isLiveTrieCountField(field) {
		return fmt.Errorf("invalid count field %q", countField)
	}

	lt.mu.Lock()
	if lt.countField == field {
		lt.mu.Unlock()
		return nil
	}
	lt.countField = field
	lt.resetLocked()
	lt.mu.Unlock()
	lt.invalidateCache()
	return nil
}

// SetHeightField changes the active height metric and starts a new baseline.
func (lt *LiveTrie) SetHeightField(heightField string) error {
	field := strings.TrimSpace(heightField)
	if field != "" && !isLiveTrieCountField(field) {
		return fmt.Errorf("invalid height field %q", heightField)
	}

	lt.mu.Lock()
	if lt.heightField == field {
		lt.mu.Unlock()
		return nil
	}
	lt.heightField = field
	lt.resetLocked()
	lt.mu.Unlock()
	lt.invalidateCache()
	return nil
}

// Reconfigure changes frame fields and clears accumulated data for a new baseline.
func (lt *LiveTrie) Reconfigure(fields []string) error {
	normalized, err := normalizeLiveTrieFields(fields)
	if err != nil {
		return err
	}

	lt.mu.Lock()
	lt.fields = slices.Clone(normalized)
	lt.resetLocked()
	lt.mu.Unlock()
	lt.invalidateCache()
	return nil
}

// Version returns the current ingest version of the trie.
func (lt *LiveTrie) Version() uint64 {
	return lt.version.Load()
}

// SnapshotJSON returns a compact JSON snapshot for the current trie version.
// Layered on top of SnapshotTree so the tree-building work is shared with
// callers that want the typed form directly.
func (lt *LiveTrie) SnapshotJSON() ([]byte, uint64) {
	version := lt.Version()
	lt.cacheMu.Lock()
	if lt.cacheVersion == version && lt.cacheJSON != nil {
		cached := slices.Clone(lt.cacheJSON)
		lt.cacheMu.Unlock()
		return cached, version
	}
	lt.cacheMu.Unlock()

	snapshot, version := lt.SnapshotTree()
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return []byte(`{}`), version
	}

	lt.cacheMu.Lock()
	// Only commit if no concurrent caller stored a newer version.
	if version >= lt.cacheVersion {
		lt.cacheVersion = version
		lt.cacheJSON = slices.Clone(payload)
	}
	lt.cacheMu.Unlock()

	return payload, version
}

// SnapshotTree returns the live trie snapshot as a typed node tree, bypassing
// the JSON round-trip. The pointer is safe to retain — buildSnapshot allocates
// fresh nodes per snapshot, and the trie never mutates a previously returned
// tree. The TUI uses this on a background goroutine so per-tick refreshes don't
// block the Bubble Tea update loop.
func (lt *LiveTrie) SnapshotTree() (*SnapshotNode, uint64) {
	version := lt.Version()
	lt.treeCacheMu.Lock()
	if lt.treeVersion == version && lt.treeCache != nil {
		tree := lt.treeCache
		lt.treeCacheMu.Unlock()
		return tree, version
	}
	lt.treeCacheMu.Unlock()

	lt.mu.RLock()
	version = lt.version.Load()
	rootTotal := subtreeTotal(lt.root)
	tree := buildSnapshot(lt.root, 0, liveTrieMinFraction, rootTotal)
	lt.mu.RUnlock()

	lt.treeCacheMu.Lock()
	// Only commit if no concurrent caller stored a newer version.
	if version >= lt.treeVersion {
		lt.treeVersion = version
		lt.treeCache = tree
	}
	lt.treeCacheMu.Unlock()
	return tree, version
}

func eventPairToRecord(ep *event.Pair) IterRecord {
	return IterRecord{
		Path:    ep.FileName(),
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

func (lt *LiveTrie) buildFrames(record IterRecord) []string {
	frames := make([]string, 0, len(lt.fields))
	for _, fieldName := range lt.fields {
		value, err := record.StringByName(fieldName)
		if err != nil {
			continue
		}
		for _, part := range strings.Split(value, ";") {
			if part != "" {
				frames = append(frames, part)
			}
		}
	}
	return frames
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

func subtreeTotal(node *trieNode) uint64 {
	total := node.value
	for _, child := range node.children {
		total += subtreeTotal(child)
	}
	return total
}

func buildSnapshot(node *trieNode, depth int, minFraction float64, rootTotal uint64) *SnapshotNode {
	snapshot, _, _ := buildSnapshotWithTotal(node, depth, minFraction, rootTotal, false)
	return snapshot
}

type childSnapshotState struct {
	node        *trieNode
	snapshot    *SnapshotNode
	total       uint64
	heightTotal uint64
}

func buildSnapshotWithTotal(node *trieNode, depth int, minFraction float64, rootTotal uint64, forceKeep bool) (*SnapshotNode, uint64, uint64) {
	total := node.value
	heightTotal := node.heightValue
	children := slices.Clone(node.children)
	slices.SortFunc(children, func(a, b *trieNode) int {
		return cmp.Compare(a.name, b.name)
	})

	childStates := make([]childSnapshotState, 0, len(children))
	for _, child := range children {
		childSnapshot, childTotal, childHeightTotal := buildSnapshotWithTotal(child, depth+1, minFraction, rootTotal, false)
		total += childTotal
		heightTotal += childHeightTotal
		childStates = append(childStates, childSnapshotState{
			node:        child,
			snapshot:    childSnapshot,
			total:       childTotal,
			heightTotal: childHeightTotal,
		})
	}

	if !forceKeep && depth > 0 && rootTotal > 0 && float64(total)/float64(rootTotal) < minFraction {
		return nil, total, heightTotal
	}
	ensureFallbackVisibleChildren(childStates, depth, minFraction, rootTotal)

	childSnapshots := make([]*SnapshotNode, 0, len(childStates))
	for _, child := range childStates {
		if child.snapshot != nil {
			childSnapshots = append(childSnapshots, child.snapshot)
		}
	}

	snapshot := &SnapshotNode{
		Name:        node.name,
		Value:       node.value,
		Total:       total,
		HeightTotal: heightTotal,
	}
	if len(childSnapshots) > 0 {
		snapshot.Children = childSnapshots
	}
	return snapshot, total, heightTotal
}

func ensureFallbackVisibleChildren(children []childSnapshotState, depth int, minFraction float64, rootTotal uint64) {
	if depth > liveTrieVisibleChildrenFallbackMaxDepth {
		return
	}
	visible := 0
	for _, child := range children {
		if child.snapshot != nil {
			visible++
		}
	}
	if visible > 0 {
		return
	}

	candidates := make([]int, 0, len(children))
	for idx, child := range children {
		if child.total > 0 {
			candidates = append(candidates, idx)
		}
	}
	slices.SortFunc(candidates, func(a, b int) int {
		left := children[a]
		right := children[b]
		if left.total != right.total {
			return cmp.Compare(right.total, left.total)
		}
		return cmp.Compare(left.node.name, right.node.name)
	})

	limit := liveTrieMinVisibleChildrenWhenPruned
	if len(candidates) < limit {
		limit = len(candidates)
	}
	for i := 0; i < limit; i++ {
		idx := candidates[i]
		forced, _, _ := buildSnapshotWithTotal(children[idx].node, depth+1, minFraction, rootTotal, true)
		children[idx].snapshot = forced
	}
}
