package flamegraph

import (
	"fmt"
	"testing"
)

// seedHighCardinalityTrie fills a trie with paths distinct files spread over
// a few processes and directories — the high-cardinality shape of a long
// `comm,path` session that motivated incremental totals and
// prune-before-build snapshots.
func seedHighCardinalityTrie(tb testing.TB, lt *LiveTrie, paths int) {
	tb.Helper()
	comms := []string{"postgres", "nginx", "rsync", "java"}
	for i := 0; i < paths; i++ {
		lt.AddRecord(IterRecord{
			Comm: comms[i%len(comms)],
			Path: fmt.Sprintf("/data/d%03d/f%07d", i%200, i),
			Cnt:  Counter{Count: 1},
		})
	}
}

// BenchmarkLiveTrieSnapshotTree measures one uncached snapshot of a trie with
// many distinct paths. Every iteration adds one record so the per-version tree
// cache cannot serve it; that record is part of the measured cost but is
// negligible next to the snapshot itself.
func BenchmarkLiveTrieSnapshotTree(b *testing.B) {
	for _, paths := range []int{10_000, 100_000} {
		b.Run(fmt.Sprintf("paths=%d", paths), func(b *testing.B) {
			lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
			seedHighCardinalityTrie(b, lt, paths)
			record := IterRecord{Comm: "postgres", Path: "/data/d000/f0000000", Cnt: Counter{Count: 1}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lt.AddRecord(record)
				if tree, _ := lt.SnapshotTree(); tree == nil {
					b.Fatal("nil snapshot")
				}
			}
		})
	}
}

// BenchmarkLiveTrieAddRecord measures the per-event ingest cost on the
// `comm,path` layout, including frame construction.
func BenchmarkLiveTrieAddRecord(b *testing.B) {
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
	records := make([]IterRecord, 1024)
	for i := range records {
		records[i] = IterRecord{Comm: "postgres", Path: fmt.Sprintf("/data/d%03d/f%04d", i%16, i), Cnt: Counter{Count: 1}}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lt.AddRecord(records[i%len(records)])
	}
}

// BenchmarkLiveTrieSnapshotTreeWideFallback measures a snapshot whose
// depth-one node has a huge fan-out of children that are all below the
// pruning fraction, so the snapshot must pick the largest few as fallback.
func BenchmarkLiveTrieSnapshotTreeWideFallback(b *testing.B) {
	lt := NewLiveTrie([]string{"path"}, "count", "")
	for i := 0; i < 100_000; i++ {
		lt.AddRecord(IterRecord{Path: fmt.Sprintf("/stress/%06d", i), Cnt: Counter{Count: 1}})
	}
	record := IterRecord{Path: "/stress/000000", Cnt: Counter{Count: 1}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lt.AddRecord(record)
		if tree, _ := lt.SnapshotTree(); tree == nil {
			b.Fatal("nil snapshot")
		}
	}
}
