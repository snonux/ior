package flamegraph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
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

func TestLiveTrieResetClearsDataAndAdvancesVersion(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))
	lt.Ingest(newTestPair("svc", 42, 1002, "/tmp/b", 1, 1, 1))

	before := lt.Version()
	if before == 0 {
		t.Fatalf("expected non-zero version before reset")
	}

	lt.Reset()
	if got := lt.Version(); got != before+1 {
		t.Fatalf("version after reset = %d, want %d", got, before+1)
	}

	snap := decodeLiveSnapshot(t, lt)
	if snap.Total != 0 {
		t.Fatalf("snapshot total after reset = %d, want 0", snap.Total)
	}

	lt.Ingest(newTestPair("svc", 42, 1003, "/tmp/c", 1, 1, 1))
	next := decodeLiveSnapshot(t, lt)
	if next.Total != 1 {
		t.Fatalf("snapshot total after new baseline ingest = %d, want 1", next.Total)
	}
}

func TestLiveTrieReconfigureChangesOrderAndResets(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "pid"}, "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))

	if err := lt.Reconfigure([]string{"path", "comm"}); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if got := lt.Fields(); len(got) != 2 || got[0] != "path" || got[1] != "comm" {
		t.Fatalf("fields after reconfigure = %v, want [path comm]", got)
	}

	empty := decodeLiveSnapshot(t, lt)
	if empty.Total != 0 {
		t.Fatalf("snapshot total after reconfigure = %d, want 0", empty.Total)
	}

	lt.Ingest(newTestPair("svc", 42, 1002, "/tmp/a", 1, 1, 1))
	snap := decodeLiveSnapshot(t, lt)
	findSnapshotPath(t, &snap, "/tmp", "/a", "svc")
}

func TestLiveTrieReconfigureRejectsInvalidFields(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")

	cases := [][]string{
		nil,
		{},
		{"comm", "comm"},
		{"comm", ""},
		{"comm", "bogus"},
	}
	for _, tc := range cases {
		if err := lt.Reconfigure(tc); err == nil {
			t.Fatalf("expected error for fields=%v", tc)
		}
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

func TestLiveTrieStressHighRateConcurrentSnapshot(t *testing.T) {
	if os.Getenv("IOR_STRESS_TEST") != "1" {
		t.Skip("set IOR_STRESS_TEST=1 to run stress test")
	}

	const (
		totalEvents     = 50000
		snapshotReaders = 3
		maxMemGrowth    = 512 << 20
	)

	lt := NewLiveTrie([]string{"path", "pid"}, "count")
	var startMem runtime.MemStats
	runtime.ReadMemStats(&startMem)

	done := make(chan struct{})
	var snapshots atomic.Int64
	errCh := make(chan error, snapshotReaders)
	var readersWG sync.WaitGroup
	readersWG.Add(snapshotReaders)
	for i := 0; i < snapshotReaders; i++ {
		go func() {
			defer readersWG.Done()
			ticker := time.NewTicker(2 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					payload, _ := lt.SnapshotJSON()
					var snap trieSnapshot
					if err := json.Unmarshal(payload, &snap); err != nil {
						errCh <- fmt.Errorf("snapshot json invalid: %w", err)
						return
					}
					snapshots.Add(1)
				}
			}
		}()
	}

	start := time.Now()
	for i := 0; i < totalEvents; i++ {
		pid := uint32(1000 + (i % 32))
		tid := uint32(100000 + i)
		path := fmt.Sprintf("/stress/%05d", i)
		lt.Ingest(newTestPair("qa-load", pid, tid, path, 1, 1, 1))
	}
	ingestDuration := time.Since(start)

	close(done)
	readersWG.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	if got := lt.Version(); got != totalEvents {
		t.Fatalf("version = %d, want %d", got, totalEvents)
	}
	if snapshots.Load() == 0 {
		t.Fatalf("expected at least one concurrent snapshot read")
	}

	final := decodeLiveSnapshot(t, lt)
	if final.Total != totalEvents {
		t.Fatalf("final total = %d, want %d", final.Total, totalEvents)
	}

	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)
	if endMem.Alloc > startMem.Alloc+maxMemGrowth {
		t.Fatalf("memory growth too high: start=%d end=%d limit=%d", startMem.Alloc, endMem.Alloc, startMem.Alloc+maxMemGrowth)
	}

	rate := float64(totalEvents) / ingestDuration.Seconds()
	t.Logf("stress ingest rate: %.0f events/sec (%d events in %s)", rate, totalEvents, ingestDuration)
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
