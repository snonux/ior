package flamegraph

import (
	"slices"
	"sync"
	"sync/atomic"
)

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

// Version returns the current ingest version of the trie.
func (lt *LiveTrie) Version() uint64 {
	return lt.version.Load()
}
