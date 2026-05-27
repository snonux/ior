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
	func() {
		lt.cacheMu.Lock()
		defer lt.cacheMu.Unlock()
		lt.cacheVersion = 0
		lt.cacheJSON = nil
	}()
	func() {
		lt.treeCacheMu.Lock()
		defer lt.treeCacheMu.Unlock()
		lt.treeVersion = 0
		lt.treeCache = nil
	}()
}

// Ingest adds one event pair into the live trie.
func (lt *LiveTrie) Ingest(ep *event.Pair) {
	record := eventPairToRecord(ep)
	lt.AddRecord(record)
}

func (lt *LiveTrie) addRecordConfig() ([]string, string, string) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	fields := slices.Clone(lt.fields)
	countField := lt.countField
	heightField := lt.heightField
	return fields, countField, heightField
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

// SnapshotJSON returns a compact JSON snapshot for the current trie version.
// Layered on top of SnapshotTree so the tree-building work is shared with
// callers that want the typed form directly.
func (lt *LiveTrie) SnapshotJSON() ([]byte, uint64) {
	version := lt.Version()
	cached, ok := func() ([]byte, bool) {
		lt.cacheMu.Lock()
		defer lt.cacheMu.Unlock()
		if lt.cacheVersion == version && lt.cacheJSON != nil {
			return slices.Clone(lt.cacheJSON), true
		}
		return nil, false
	}()
	if ok {
		return cached, version
	}

	snapshot, version := lt.SnapshotTree()
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return []byte(`{}`), version
	}

	lt.cacheMu.Lock()
	defer lt.cacheMu.Unlock()
	// Only commit if no concurrent caller stored a newer version.
	if version >= lt.cacheVersion {
		lt.cacheVersion = version
		lt.cacheJSON = slices.Clone(payload)
	}

	return payload, version
}

// SnapshotTree returns the live trie snapshot as a typed node tree, bypassing
// the JSON round-trip. The pointer is safe to retain — buildSnapshot allocates
// fresh nodes per snapshot, and the trie never mutates a previously returned
// tree. The TUI uses this on a background goroutine so per-tick refreshes don't
// block the Bubble Tea update loop.
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
		rootTotal := subtreeTotal(lt.root)
		return currentVersion, buildSnapshot(lt.root, 0, liveTrieMinFraction, rootTotal)
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

func buildFrames(record IterRecord, fields []string) []string {
	frames := make([]string, 0, len(fields))
	for _, fieldName := range fields {
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
