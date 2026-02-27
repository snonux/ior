package flamegraph

import (
	"bytes"
	"encoding/json"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
	"sync"
	"testing"
)

func TestLiveTrieIngestAndSnapshotRoundTrip(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "pid"}, "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 2, 3))

	snap := decodeLiveSnapshot(t, lt)
	if snap.Total != 1 {
		t.Fatalf("root total = %d, want 1", snap.Total)
	}
	leaf := findSnapshotPath(t, &snap, "svc", "42")
	if leaf.Value != 1 {
		t.Fatalf("leaf value = %d, want 1", leaf.Value)
	}
	if leaf.Total != 1 {
		t.Fatalf("leaf total = %d, want 1", leaf.Total)
	}
}

func TestLiveTrieIngestIsAdditive(t *testing.T) {
	lt := NewLiveTrie([]string{"path"}, "bytes")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 2, 10))
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 3, 4, 15))

	snap := decodeLiveSnapshot(t, lt)
	leaf := findSnapshotPath(t, &snap, "/tmp", "/a")
	if leaf.Value != 25 {
		t.Fatalf("leaf bytes value = %d, want 25", leaf.Value)
	}
	if snap.Total != 25 {
		t.Fatalf("root total = %d, want 25", snap.Total)
	}
}

func TestLiveTrieVersionIncrementsPerIngest(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	if got := lt.Version(); got != 0 {
		t.Fatalf("initial version = %d, want 0", got)
	}
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))
	lt.Ingest(newTestPair("svc", 42, 1002, "/tmp/b", 1, 1, 1))

	if got := lt.Version(); got != 2 {
		t.Fatalf("version = %d, want 2", got)
	}
}

func TestLiveTrieSnapshotJSONCaching(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))

	first, version1 := lt.SnapshotJSON()
	second, version2 := lt.SnapshotJSON()

	if version1 != version2 {
		t.Fatalf("versions differ: %d != %d", version1, version2)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("snapshot bytes differ across cached call")
	}
}

func TestLiveTrieSnapshotJSONPrunesTinyNodes(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	for i := 0; i < 2000; i++ {
		lt.Ingest(newTestPair("big", 42, uint32(1000+i), "/tmp/a", 1, 1, 1))
	}
	lt.Ingest(newTestPair("tiny", 42, 99999, "/tmp/z", 1, 1, 1))

	snap := decodeLiveSnapshot(t, lt)
	if findSnapshotChild(&snap, "big") == nil {
		t.Fatalf("expected big node in snapshot")
	}
	if findSnapshotChild(&snap, "tiny") != nil {
		t.Fatalf("tiny node should be pruned at <0.1%% of root total")
	}
}

func TestLiveTrieConcurrentIngestAndSnapshot(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "pid"}, "count")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			lt.Ingest(newTestPair("svc", 42, uint32(1000+i), "/tmp/a", 1, 1, 1))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			payload, _ := lt.SnapshotJSON()
			var snap trieSnapshot
			if err := json.Unmarshal(payload, &snap); err != nil {
				t.Errorf("unmarshal snapshot: %v", err)
				return
			}
		}
	}()

	wg.Wait()
	if lt.Version() == 0 {
		t.Fatalf("expected version > 0 after concurrent ingest")
	}
}

func newTestPair(comm string, pid uint32, tid uint32, path string, duration uint64, gap uint64, bytesCnt uint64) *event.Pair {
	enter := &types.OpenEvent{
		TraceId: types.SYS_ENTER_OPENAT,
		Pid:     pid,
		Tid:     tid,
	}
	exit := &types.RetEvent{
		TraceId: types.SYS_EXIT_OPENAT,
		Pid:     pid,
		Tid:     tid,
	}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(3, path, 0)
	pair.Comm = comm
	pair.Duration = duration
	pair.DurationToPrev = gap
	pair.Bytes = bytesCnt
	return pair
}

func decodeLiveSnapshot(t *testing.T, lt *LiveTrie) trieSnapshot {
	t.Helper()
	payload, _ := lt.SnapshotJSON()
	var snap trieSnapshot
	if err := json.Unmarshal(payload, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	return snap
}

func findSnapshotPath(t *testing.T, root *trieSnapshot, names ...string) *trieSnapshot {
	t.Helper()
	node := root
	for _, name := range names {
		node = findSnapshotChild(node, name)
		if node == nil {
			t.Fatalf("missing snapshot node %q", name)
		}
	}
	return node
}

func findSnapshotChild(node *trieSnapshot, name string) *trieSnapshot {
	for _, child := range node.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}
