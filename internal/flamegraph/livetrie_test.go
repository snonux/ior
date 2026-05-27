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
	lt := NewLiveTrie([]string{"comm", "pid"}, "count", "count")
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
	lt := NewLiveTrie([]string{"path"}, "bytes", "bytes")
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

func TestLiveTrieIngestCopiesBeforeRecycle(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "count")

	pair := newTestPair("svc", 42, 1001, "/tmp/a", 1, 2, 3)
	lt.Ingest(pair)
	pair.Recycle()

	snap := decodeLiveSnapshot(t, lt)
	leaf := findSnapshotPath(t, &snap, "svc", "/tmp", "/a")
	if got, want := leaf.Value, uint64(1); got != want {
		t.Fatalf("leaf value after recycle = %d, want %d", got, want)
	}
	if got, want := leaf.Total, uint64(1); got != want {
		t.Fatalf("leaf total after recycle = %d, want %d", got, want)
	}
}

func TestLiveTrieCommTracepointPathAggregatesSameSyscallAcrossPaths(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count", "count")
	lt.AddRecord(IterRecord{
		Path:    "/srv/a",
		TraceID: types.SYS_ENTER_READ,
		Comm:    "svc",
		Pid:     1001,
		Tid:     1001,
		Cnt:     Counter{Count: 1},
	})
	lt.AddRecord(IterRecord{
		Path:    "/srv/b",
		TraceID: types.SYS_ENTER_READ,
		Comm:    "svc",
		Pid:     1002,
		Tid:     1002,
		Cnt:     Counter{Count: 1},
	})

	snap := decodeLiveSnapshot(t, lt)
	commNode := findSnapshotPath(t, &snap, "svc")
	if len(commNode.Children) != 1 {
		t.Fatalf("expected one syscall child under comm node, got %d", len(commNode.Children))
	}
	syscallNode := commNode.Children[0]
	if got, want := syscallNode.Name, "enter_read"; got != want {
		t.Fatalf("syscall child name = %q, want %q", got, want)
	}
	if got, want := syscallNode.Total, uint64(2); got != want {
		t.Fatalf("syscall aggregate total = %d, want %d", got, want)
	}
}

func TestLiveTrieVersionIncrementsPerIngest(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
	if got := lt.Version(); got != 0 {
		t.Fatalf("initial version = %d, want 0", got)
	}
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))
	lt.Ingest(newTestPair("svc", 42, 1002, "/tmp/b", 1, 1, 1))

	if got := lt.Version(); got != 2 {
		t.Fatalf("version = %d, want 2", got)
	}
}

func TestLiveTrieAddRecordIncrementsVersion(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	lt.AddRecord(IterRecord{
		Path:    "/tmp/demo/read",
		TraceID: types.SYS_ENTER_READ,
		Comm:    "demo",
		Pid:     1001,
		Tid:     1001,
		Cnt:     Counter{Count: 7, Duration: 70, DurationToPrev: 14, Bytes: 28},
	})

	if got := lt.Version(); got != 1 {
		t.Fatalf("version = %d, want 1", got)
	}
	snap := decodeLiveSnapshot(t, lt)
	if snap.Total != 7 {
		t.Fatalf("root total = %d, want 7", snap.Total)
	}
}

func TestSeedTestFlameDataBuildsStaticFixture(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	SeedTestFlameData(lt)

	if got := lt.Version(); got == 0 {
		t.Fatalf("expected seed fixture to add records")
	}
	snap := decodeLiveSnapshot(t, lt)
	if snap.Total == 0 {
		t.Fatalf("expected non-empty seeded snapshot")
	}
	if findSnapshotChild(&snap, "api") == nil {
		t.Fatalf("expected seeded snapshot to include api branch")
	}
	if findSnapshotChild(&snap, "worker") == nil {
		t.Fatalf("expected seeded snapshot to include worker branch")
	}
}

func TestSeedTestLiveFlameDataVariesByTick(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")

	SeedTestLiveFlameData(lt, 0)
	snapTick0 := decodeLiveSnapshot(t, lt)
	apiTick0 := findSnapshotPath(t, &snapTick0, "api").Total
	workerTick0 := findSnapshotPath(t, &snapTick0, "worker").Total

	lt.Reset()
	SeedTestLiveFlameData(lt, 1)
	snapTick1 := decodeLiveSnapshot(t, lt)
	apiTick1 := findSnapshotPath(t, &snapTick1, "api").Total
	workerTick1 := findSnapshotPath(t, &snapTick1, "worker").Total

	if apiTick0 == apiTick1 && workerTick0 == workerTick1 {
		t.Fatalf("expected phase shift to alter branch totals, got api=%d worker=%d for both ticks", apiTick0, workerTick0)
	}
	if apiTick0 <= workerTick0 {
		t.Fatalf("expected api to dominate at tick 0, got api=%d worker=%d", apiTick0, workerTick0)
	}
	if workerTick1 <= apiTick1 {
		t.Fatalf("expected worker to dominate at tick 1, got worker=%d api=%d", workerTick1, apiTick1)
	}
}

func TestLiveTrieResetClearsDataAndAdvancesVersion(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
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
	lt := NewLiveTrie([]string{"comm", "pid"}, "count", "count")
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
	lt := NewLiveTrie([]string{"comm"}, "count", "count")

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

func TestLiveTrieSetCountFieldSwitchesMetricAndResetsBaseline(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 10, 1, 64))

	initial := decodeLiveSnapshot(t, lt)
	if got, want := initial.Total, uint64(1); got != want {
		t.Fatalf("count snapshot total = %d, want %d", got, want)
	}

	if err := lt.SetCountField("bytes"); err != nil {
		t.Fatalf("set count field: %v", err)
	}
	if got, want := lt.CountField(), "bytes"; got != want {
		t.Fatalf("count field = %q, want %q", got, want)
	}

	empty := decodeLiveSnapshot(t, lt)
	if got := empty.Total; got != 0 {
		t.Fatalf("expected reset baseline after metric switch, total=%d", got)
	}

	lt.Ingest(newTestPair("svc", 42, 1002, "/tmp/b", 10, 1, 64))
	bytesSnap := decodeLiveSnapshot(t, lt)
	if got, want := bytesSnap.Total, uint64(64); got != want {
		t.Fatalf("bytes snapshot total = %d, want %d", got, want)
	}
	leaf := findSnapshotPath(t, &bytesSnap, "svc")
	if got, want := leaf.Total, uint64(64); got != want {
		t.Fatalf("bytes leaf total = %d, want %d", got, want)
	}
}

func TestLiveTrieSetCountFieldRejectsInvalidValue(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))
	beforeVersion := lt.Version()

	if err := lt.SetCountField("bogus"); err == nil {
		t.Fatalf("expected invalid count field error")
	}
	if got, want := lt.CountField(), "count"; got != want {
		t.Fatalf("count field changed unexpectedly: got %q want %q", got, want)
	}
	if got := lt.Version(); got != beforeVersion {
		t.Fatalf("version changed on invalid count field: got %d want %d", got, beforeVersion)
	}
}

func TestLiveTrieHeightFieldTracksIndependentMetric(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "bytes")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 10, 1, 64))
	lt.Ingest(newTestPair("svc", 42, 1002, "/tmp/b", 10, 1, 128))

	snap := decodeLiveSnapshot(t, lt)
	if got, want := snap.Total, uint64(2); got != want {
		t.Fatalf("root total = %d, want %d", got, want)
	}
	if got, want := snap.HeightTotal, uint64(192); got != want {
		t.Fatalf("root height total = %d, want %d", got, want)
	}
	leaf := findSnapshotPath(t, &snap, "svc")
	if got, want := leaf.Total, uint64(2); got != want {
		t.Fatalf("leaf total = %d, want %d", got, want)
	}
	if got, want := leaf.HeightTotal, uint64(192); got != want {
		t.Fatalf("leaf height total = %d, want %d", got, want)
	}
}

func TestLiveTrieSetHeightFieldSwitchesMetricAndResetsBaseline(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 10, 1, 64))

	initial := decodeLiveSnapshot(t, lt)
	if got, want := initial.HeightTotal, uint64(1); got != want {
		t.Fatalf("initial height total = %d, want %d", got, want)
	}

	if err := lt.SetHeightField("bytes"); err != nil {
		t.Fatalf("set height field: %v", err)
	}
	if got, want := lt.HeightField(), "bytes"; got != want {
		t.Fatalf("height field = %q, want %q", got, want)
	}

	empty := decodeLiveSnapshot(t, lt)
	if got := empty.Total; got != 0 {
		t.Fatalf("expected reset baseline after height metric switch, total=%d", got)
	}
	if got := empty.HeightTotal; got != 0 {
		t.Fatalf("expected reset baseline after height metric switch, height total=%d", got)
	}

	lt.Ingest(newTestPair("svc", 42, 1002, "/tmp/b", 10, 1, 64))
	next := decodeLiveSnapshot(t, lt)
	if got, want := next.Total, uint64(1); got != want {
		t.Fatalf("total after switch = %d, want %d", got, want)
	}
	if got, want := next.HeightTotal, uint64(64); got != want {
		t.Fatalf("height total after switch = %d, want %d", got, want)
	}
}

func TestLiveTrieSetHeightFieldRejectsInvalidValue(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))
	beforeVersion := lt.Version()

	if err := lt.SetHeightField("bogus"); err == nil {
		t.Fatalf("expected invalid height field error")
	}
	if got, want := lt.HeightField(), "count"; got != want {
		t.Fatalf("height field changed unexpectedly: got %q want %q", got, want)
	}
	if got := lt.Version(); got != beforeVersion {
		t.Fatalf("version changed on invalid height field: got %d want %d", got, beforeVersion)
	}
}

func TestLiveTrieSetHeightFieldNoopKeepsBaseline(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "bytes")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 10, 1, 64))
	beforeVersion := lt.Version()

	if err := lt.SetHeightField("bytes"); err != nil {
		t.Fatalf("set height field noop: %v", err)
	}
	if got := lt.Version(); got != beforeVersion {
		t.Fatalf("version changed on noop height field set: got %d want %d", got, beforeVersion)
	}

	snap := decodeLiveSnapshot(t, lt)
	if got, want := snap.Total, uint64(1); got != want {
		t.Fatalf("total after noop height switch = %d, want %d", got, want)
	}
	if got, want := snap.HeightTotal, uint64(64); got != want {
		t.Fatalf("height total after noop height switch = %d, want %d", got, want)
	}
}

func TestLiveTrieHeightFieldEmptyDisablesHeightTotals(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 10, 1, 64))

	snap := decodeLiveSnapshot(t, lt)
	if got, want := snap.Total, uint64(1); got != want {
		t.Fatalf("root total = %d, want %d", got, want)
	}
	if got := snap.HeightTotal; got != 0 {
		t.Fatalf("root height total = %d, want 0 when height metric disabled", got)
	}
}

func TestLiveTrieSnapshotHeightTotalsAccumulateAcrossBranches(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "pid"}, "count", "bytes")
	lt.Ingest(newTestPair("svc", 101, 1001, "/tmp/a", 10, 1, 100))
	lt.Ingest(newTestPair("svc", 102, 1002, "/tmp/b", 10, 1, 40))
	lt.Ingest(newTestPair("db", 201, 1003, "/tmp/c", 10, 1, 10))

	snap := decodeLiveSnapshot(t, lt)
	if got, want := snap.Total, uint64(3); got != want {
		t.Fatalf("root total = %d, want %d", got, want)
	}
	if got, want := snap.HeightTotal, uint64(150); got != want {
		t.Fatalf("root height total = %d, want %d", got, want)
	}

	svc := findSnapshotPath(t, &snap, "svc")
	if got, want := svc.Total, uint64(2); got != want {
		t.Fatalf("svc total = %d, want %d", got, want)
	}
	if got, want := svc.HeightTotal, uint64(140); got != want {
		t.Fatalf("svc height total = %d, want %d", got, want)
	}

	db := findSnapshotPath(t, &snap, "db")
	if got, want := db.Total, uint64(1); got != want {
		t.Fatalf("db total = %d, want %d", got, want)
	}
	if got, want := db.HeightTotal, uint64(10); got != want {
		t.Fatalf("db height total = %d, want %d", got, want)
	}
}

func TestLiveTrieSnapshotJSONCaching(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
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
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
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

func TestLiveTrieSnapshotJSONKeepsFallbackChildrenWhenAllAreTinyAtRoot(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "count")
	const total = 6000
	for i := 0; i < total; i++ {
		comm := fmt.Sprintf("svc-%04d", i)
		lt.Ingest(newTestPair(comm, 42, uint32(100000+i), "/tmp/a", 1, 1, 1))
	}

	snap := decodeLiveSnapshot(t, lt)
	if len(snap.Children) == 0 {
		t.Fatalf("expected fallback root children when pruning would hide every branch")
	}
	if got, want := len(snap.Children), liveTrieMinVisibleChildrenWhenPruned; got != want {
		t.Fatalf("expected fallback to keep %d root children, got %d", want, got)
	}
}

func TestLiveTrieSnapshotJSONKeepsFallbackChildrenAtDepthOne(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "pid"}, "count", "count")
	const total = 6000
	for i := 0; i < total; i++ {
		pid := uint32(100000 + i)
		lt.Ingest(newTestPair("svc", pid, pid, "/tmp/a", 1, 1, 1))
	}

	snap := decodeLiveSnapshot(t, lt)
	commNode := findSnapshotPath(t, &snap, "svc")
	if len(commNode.Children) == 0 {
		t.Fatalf("expected fallback depth-one children for pid branches")
	}
	if got, want := len(commNode.Children), liveTrieMinVisibleChildrenWhenPruned; got != want {
		t.Fatalf("expected fallback to keep %d depth-one children, got %d", want, got)
	}
}

func TestLiveTrieConcurrentIngestAndSnapshot(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "pid"}, "count", "count")

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
			var snap SnapshotNode
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

func TestLiveTrieConcurrentAddRecordAndMetricToggle(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "pid"}, "count", "count")

	const iterations = 1500
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			lt.AddRecord(IterRecord{
				Comm:    "svc",
				Pid:     42,
				TraceID: types.SYS_ENTER_READ,
				Cnt: Counter{
					Count:          1,
					Bytes:          2,
					Duration:       3,
					DurationToPrev: 4,
				},
			})
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			field := "count"
			if i%2 == 1 {
				field = "bytes"
			}
			if err := lt.SetCountField(field); err != nil {
				errCh <- fmt.Errorf("set count field %q: %w", field, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			field := "count"
			if i%2 == 1 {
				field = "bytes"
			}
			if err := lt.SetHeightField(field); err != nil {
				errCh <- fmt.Errorf("set height field %q: %w", field, err)
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	payload, _ := lt.SnapshotJSON()
	var snap SnapshotNode
	if err := json.Unmarshal(payload, &snap); err != nil {
		t.Fatalf("unmarshal snapshot after concurrent updates: %v", err)
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

	lt := NewLiveTrie([]string{"path", "pid"}, "count", "count")
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
					var snap SnapshotNode
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

func decodeLiveSnapshot(t *testing.T, lt *LiveTrie) SnapshotNode {
	t.Helper()
	payload, _ := lt.SnapshotJSON()
	var snap SnapshotNode
	if err := json.Unmarshal(payload, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	return snap
}

func findSnapshotPath(t *testing.T, root *SnapshotNode, names ...string) *SnapshotNode {
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

func findSnapshotChild(node *SnapshotNode, name string) *SnapshotNode {
	for _, child := range node.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}
