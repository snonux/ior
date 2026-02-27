package flamegraph

import (
	"encoding/json"
	"fmt"
	"ior/internal/event"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

const liveTrieMinFraction = 0.001

type trieSnapshot struct {
	Name     string          `json:"n"`
	Value    uint64          `json:"v"`
	Total    uint64          `json:"t"`
	Children []*trieSnapshot `json:"c,omitempty"`
}

// LiveTrie is a thread-safe, append-only trie used for live flamegraph snapshots.
type LiveTrie struct {
	mu         sync.RWMutex
	root       *trieNode
	maxDepth   int
	version    atomic.Uint64
	fields     []string
	countField string

	// Snapshot cache avoids recomputing JSON when version is unchanged.
	cacheMu      sync.Mutex
	cacheVersion uint64
	cacheJSON    []byte
}

// NewLiveTrie constructs an empty live trie with the configured frame/count fields.
func NewLiveTrie(fields []string, countField string) *LiveTrie {
	return &LiveTrie{
		root: &trieNode{
			childMap: make(map[string]*trieNode),
		},
		fields:     slices.Clone(fields),
		countField: countField,
	}
}

func (lt *LiveTrie) addLocked(frames []string, value uint64) {
	node := lt.root
	for _, frame := range frames {
		if node.childMap == nil {
			node.childMap = make(map[string]*trieNode)
		}
		child, ok := node.childMap[frame]
		if !ok {
			child = &trieNode{
				name:     frame,
				childMap: make(map[string]*trieNode),
			}
			node.children = append(node.children, child)
			node.childMap[frame] = child
		}
		node = child
	}
	node.value += value
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
}

// Ingest adds one event pair into the live trie and recycles the pair.
func (lt *LiveTrie) Ingest(ep *event.Pair) {
	record := eventPairToRecord(ep)
	value := record.Cnt.ValueByName(lt.countField)

	lt.mu.Lock()
	frames := lt.buildFrames(record)
	lt.addLocked(frames, value)
	lt.version.Add(1)
	lt.mu.Unlock()

	ep.Recycle()
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
func (lt *LiveTrie) SnapshotJSON() ([]byte, uint64) {
	version := lt.Version()
	lt.cacheMu.Lock()
	if lt.cacheVersion == version && lt.cacheJSON != nil {
		cached := slices.Clone(lt.cacheJSON)
		lt.cacheMu.Unlock()
		return cached, version
	}
	lt.cacheMu.Unlock()

	lt.mu.RLock()
	version = lt.version.Load()
	rootTotal := subtreeTotal(lt.root)
	snapshot := buildSnapshot(lt.root, 0, liveTrieMinFraction, rootTotal)
	lt.mu.RUnlock()

	payload, err := json.Marshal(snapshot)
	if err != nil {
		return []byte(`{}`), version
	}

	lt.cacheMu.Lock()
	lt.cacheVersion = version
	lt.cacheJSON = slices.Clone(payload)
	lt.cacheMu.Unlock()

	return payload, version
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
	switch field {
	case "path", "comm", "tracepoint", "pid", "tid", "flags":
		return true
	default:
		return false
	}
}

func subtreeTotal(node *trieNode) uint64 {
	total := node.value
	for _, child := range node.children {
		total += subtreeTotal(child)
	}
	return total
}

func buildSnapshot(node *trieNode, depth int, minFraction float64, rootTotal uint64) *trieSnapshot {
	snapshot, _ := buildSnapshotWithTotal(node, depth, minFraction, rootTotal)
	return snapshot
}

func buildSnapshotWithTotal(node *trieNode, depth int, minFraction float64, rootTotal uint64) (*trieSnapshot, uint64) {
	total := node.value
	children := slices.Clone(node.children)
	sort.Slice(children, func(i, j int) bool {
		return children[i].name < children[j].name
	})

	childSnapshots := make([]*trieSnapshot, 0, len(children))
	for _, child := range children {
		childSnapshot, childTotal := buildSnapshotWithTotal(child, depth+1, minFraction, rootTotal)
		total += childTotal
		if childSnapshot != nil {
			childSnapshots = append(childSnapshots, childSnapshot)
		}
	}

	if depth > 0 && rootTotal > 0 && float64(total)/float64(rootTotal) < minFraction {
		return nil, total
	}

	snapshot := &trieSnapshot{
		Name:  node.name,
		Value: node.value,
		Total: total,
	}
	if len(childSnapshots) > 0 {
		snapshot.Children = childSnapshots
	}
	return snapshot, total
}
