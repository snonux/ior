package statsengine

import (
	"fmt"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
	"reflect"
	"testing"
)

func TestFileRankerHeapEviction(t *testing.T) {
	r := newFileRankerWithConfig(2)

	r.Add(newFilePair("/a", 10, 1, types.READ_CLASSIFIED))
	r.Add(newFilePair("/b", 10, 1, types.READ_CLASSIFIED))
	r.Add(newFilePair("/b", 10, 1, types.READ_CLASSIFIED))
	r.Add(newFilePair("/c", 10, 1, types.READ_CLASSIFIED))
	r.Add(newFilePair("/c", 10, 1, types.READ_CLASSIFIED))
	r.Add(newFilePair("/c", 10, 1, types.READ_CLASSIFIED))

	got := paths(r.Snapshot())
	want := []string{"/c", "/b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected top-n paths: got %v want %v", got, want)
	}
}

func TestFileRankerRankingCorrectness(t *testing.T) {
	r := newFileRankerWithConfig(3)

	r.Add(newFilePair("/read", 20, 11, types.READ_CLASSIFIED))
	r.Add(newFilePair("/read", 10, 9, types.READ_CLASSIFIED))
	r.Add(newFilePair("/write", 25, 7, types.WRITE_CLASSIFIED))
	r.Add(newFilePair("/write", 15, 3, types.WRITE_CLASSIFIED))
	r.Add(newFilePair("/xfer", 40, 5, types.TRANSFER_CLASSIFIED))
	r.Add(newFilePair("/xfer", 60, 6, types.TRANSFER_CLASSIFIED))

	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(snap))
	}

	gotOrder := paths(snap)
	wantOrder := []string{"/read", "/write", "/xfer"}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("unexpected ranking order: got %v want %v", gotOrder, wantOrder)
	}

	byPath := make(map[string]FileSnapshot, len(snap))
	for _, row := range snap {
		byPath[row.Path] = row
	}

	readRow := byPath["/read"]
	if readRow.Accesses != 2 || readRow.BytesRead != 20 || readRow.BytesWritten != 0 || readRow.MaxLatencyNs != 20 {
		t.Fatalf("unexpected /read stats: %+v", readRow)
	}
	if readRow.AvgLatencyNs != 15 {
		t.Fatalf("unexpected /read avg latency: %v", readRow.AvgLatencyNs)
	}

	writeRow := byPath["/write"]
	if writeRow.BytesRead != 0 || writeRow.BytesWritten != 10 {
		t.Fatalf("unexpected /write bytes split: %+v", writeRow)
	}

	xferRow := byPath["/xfer"]
	if xferRow.BytesRead != 11 || xferRow.BytesWritten != 11 {
		t.Fatalf("unexpected /xfer bytes split: %+v", xferRow)
	}
	if xferRow.AvgLatencyNs != 50 {
		t.Fatalf("unexpected /xfer avg latency: %v", xferRow.AvgLatencyNs)
	}
}

func TestFileRankerIgnoresInvalidFileData(t *testing.T) {
	r := newFileRankerWithConfig(3)

	r.Add(nil)
	r.Add(&event.Pair{})
	r.Add(&event.Pair{File: file.NewFd(1, "", -1), Duration: 10, Bytes: 1, ExitEv: &types.RetEvent{RetType: types.READ_CLASSIFIED}})

	if got := r.Snapshot(); len(got) != 0 {
		t.Fatalf("expected empty snapshot for invalid rows, got %+v", got)
	}
}

func TestFileRankerCompactsHighCardinality(t *testing.T) {
	r := newFileRankerWithLimits(3, 5)

	// Make one file clearly hot so it must survive compaction.
	for i := 0; i < 10; i++ {
		r.Add(newFilePair("/hot", 10, 1, types.READ_CLASSIFIED))
	}
	for i := 0; i < 200; i++ {
		r.Add(newFilePair(fmt.Sprintf("/tmp/file-%d", i), 1, 1, types.READ_CLASSIFIED))
	}

	if len(r.byPath) > r.maxSeen {
		t.Fatalf("cardinality guard failed: byPath=%d maxSeen=%d", len(r.byPath), r.maxSeen)
	}

	snap := r.Snapshot()
	if len(snap) == 0 || snap[0].Path != "/hot" {
		t.Fatalf("expected hot file to remain top-ranked after compaction, got %+v", snap)
	}
}

func newFilePair(path string, duration uint64, bytes uint64, retType uint32) *event.Pair {
	return &event.Pair{
		File:     file.NewFd(3, path, -1),
		Duration: duration,
		Bytes:    bytes,
		ExitEv:   &types.RetEvent{RetType: retType},
	}
}

func paths(rows []FileSnapshot) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Path)
	}
	return out
}
