package statsengine

import (
	"testing"

	"ior/internal/types"
)

func TestNewSnapshotDefensivelyCopiesSlices(t *testing.T) {
	latency := []float64{1, 2, 3}
	gap := []float64{4, 5, 6}
	throughput := []float64{7, 8, 9}
	syscalls := []SyscallSnapshot{{Name: "read", Count: 1}}
	families := []FamilySnapshot{{Family: types.FamilyPolling, Name: "Polling", Count: 3}}
	files := []FileSnapshot{{Path: "/tmp/a", Accesses: 2}}
	processes := []ProcessSnapshot{{PID: 10, Comm: "cmd"}}
	latencyBuckets := []HistogramBucketSnapshot{{Label: "[0,1)", Count: 3}}
	gapBuckets := []HistogramBucketSnapshot{{Label: "[1,10)", Count: 4}}

	s := NewSnapshotWithFamilies(
		latency,
		gap,
		throughput,
		syscalls,
		families,
		files,
		processes,
		NewHistogramSnapshot(3, latencyBuckets),
		NewHistogramSnapshot(4, gapBuckets),
	)

	latency[0] = 99
	gap[0] = 99
	throughput[0] = 99
	syscalls[0].Name = "write"
	families[0].Name = "FS"
	files[0].Path = "/tmp/b"
	processes[0].Comm = "mutated"
	latencyBuckets[0].Count = 99
	gapBuckets[0].Count = 99

	if got := s.LatencySeriesNs()[0]; got != 1 {
		t.Fatalf("latency mutated through input slice: got %v", got)
	}
	if got := s.GapSeriesNs()[0]; got != 4 {
		t.Fatalf("gap mutated through input slice: got %v", got)
	}
	if got := s.ThroughputSeriesB()[0]; got != 7 {
		t.Fatalf("throughput mutated through input slice: got %v", got)
	}
	if got := s.Syscalls()[0].Name; got != "read" {
		t.Fatalf("syscalls mutated through input slice: got %q", got)
	}
	if got := s.Families()[0].Name; got != "Polling" {
		t.Fatalf("families mutated through input slice: got %q", got)
	}
	if got := s.Files()[0].Path; got != "/tmp/a" {
		t.Fatalf("files mutated through input slice: got %q", got)
	}
	if got := s.Processes()[0].Comm; got != "cmd" {
		t.Fatalf("processes mutated through input slice: got %q", got)
	}
	if got := s.LatencyHistogram.Buckets()[0].Count; got != 3 {
		t.Fatalf("latency histogram mutated through input slice: got %d", got)
	}
	if got := s.GapHistogram.Buckets()[0].Count; got != 4 {
		t.Fatalf("gap histogram mutated through input slice: got %d", got)
	}
}

func TestSnapshotAccessorsReturnReadOnlyViews(t *testing.T) {
	s := NewSnapshotWithFamilies(
		[]float64{1},
		[]float64{2},
		[]float64{3},
		[]SyscallSnapshot{{Name: "read"}},
		[]FamilySnapshot{{Family: types.FamilyPolling, Name: "Polling"}},
		[]FileSnapshot{{Path: "/tmp/a"}},
		[]ProcessSnapshot{{Comm: "cmd"}},
		NewHistogramSnapshot(1, []HistogramBucketSnapshot{{Label: "a", Count: 1}}),
		NewHistogramSnapshot(1, []HistogramBucketSnapshot{{Label: "b", Count: 1}}),
	)

	lat := s.LatencySeriesNs()
	lat[0] = 100
	if got := s.LatencySeriesNs()[0]; got != 100 {
		t.Fatalf("expected accessor to return backing slice view, got %v", got)
	}

	syscalls := s.Syscalls()
	syscalls[0].Name = "write"
	if got := s.Syscalls()[0].Name; got != "write" {
		t.Fatalf("expected accessor to return backing slice view, got %q", got)
	}

	families := s.Families()
	families[0].Name = "Process"
	if got := s.Families()[0].Name; got != "Process" {
		t.Fatalf("expected family accessor to return backing slice view, got %q", got)
	}

	buckets := s.LatencyHistogram.Buckets()
	buckets[0].Count = 99
	if got := s.LatencyHistogram.Buckets()[0].Count; got != 99 {
		t.Fatalf("expected accessor to return backing slice view, got %d", got)
	}
}

func TestNilAccessorsRemainNil(t *testing.T) {
	s := Snapshot{}
	if got := s.LatencySeriesNs(); got != nil {
		t.Fatalf("expected nil latency series, got %#v", got)
	}
	if got := s.Syscalls(); got != nil {
		t.Fatalf("expected nil syscalls, got %#v", got)
	}
	if got := s.Families(); got != nil {
		t.Fatalf("expected nil families, got %#v", got)
	}

	h := HistogramSnapshot{}
	if got := h.Buckets(); got != nil {
		t.Fatalf("expected nil buckets, got %#v", got)
	}
}

func TestSnapshotNonIOFamilies(t *testing.T) {
	s := NewSnapshotWithFamilies(
		nil,
		nil,
		nil,
		nil,
		[]FamilySnapshot{
			{Family: types.FamilyFS, Name: "FS"},
			{Family: types.FamilyPolling, Name: "Polling"},
			{Family: types.FamilyProcess, Name: "Process"},
		},
		nil,
		nil,
		HistogramSnapshot{},
		HistogramSnapshot{},
	)

	rows := s.NonIOFamilies()
	if len(rows) != 2 {
		t.Fatalf("NonIOFamilies len = %d, want 2", len(rows))
	}
	if rows[0].Family == types.FamilyFS || rows[1].Family == types.FamilyFS {
		t.Fatalf("NonIOFamilies included FS: %+v", rows)
	}
	if got := s.NonIOFamiliesCount(); got != 2 {
		t.Fatalf("NonIOFamiliesCount = %d, want 2", got)
	}
}

func TestTopNAccessors(t *testing.T) {
	s := NewSnapshot(
		nil,
		nil,
		nil,
		[]SyscallSnapshot{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		[]FileSnapshot{{Path: "/a"}, {Path: "/b"}},
		[]ProcessSnapshot{{PID: 1}, {PID: 2}, {PID: 3}},
		HistogramSnapshot{},
		HistogramSnapshot{},
	)

	if got := s.TopNSyscalls(2); len(got) != 2 {
		t.Fatalf("expected 2 top syscalls, got %d", len(got))
	}
	if got := s.TopNFiles(10); len(got) != 2 {
		t.Fatalf("expected all files when n exceeds len, got %d", len(got))
	}
	if got := s.TopNProcesses(0); got != nil {
		t.Fatalf("expected nil when n<=0, got %#v", got)
	}
}
