package statsengine

import "testing"

func TestNewSnapshotDefensivelyCopiesSlices(t *testing.T) {
	latency := []float64{1, 2, 3}
	gap := []float64{4, 5, 6}
	throughput := []float64{7, 8, 9}
	syscalls := []SyscallSnapshot{{Name: "read", Count: 1}}
	files := []FileSnapshot{{Path: "/tmp/a", Accesses: 2}}
	processes := []ProcessSnapshot{{PID: 10, Comm: "cmd"}}
	latencyBuckets := []HistogramBucketSnapshot{{Label: "[0,1)", Count: 3}}
	gapBuckets := []HistogramBucketSnapshot{{Label: "[1,10)", Count: 4}}

	s := NewSnapshot(
		latency,
		gap,
		throughput,
		syscalls,
		files,
		processes,
		NewHistogramSnapshot(3, latencyBuckets),
		NewHistogramSnapshot(4, gapBuckets),
	)

	latency[0] = 99
	gap[0] = 99
	throughput[0] = 99
	syscalls[0].Name = "write"
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

func TestSnapshotAccessorsReturnCopies(t *testing.T) {
	s := NewSnapshot(
		[]float64{1},
		[]float64{2},
		[]float64{3},
		[]SyscallSnapshot{{Name: "read"}},
		[]FileSnapshot{{Path: "/tmp/a"}},
		[]ProcessSnapshot{{Comm: "cmd"}},
		NewHistogramSnapshot(1, []HistogramBucketSnapshot{{Label: "a", Count: 1}}),
		NewHistogramSnapshot(1, []HistogramBucketSnapshot{{Label: "b", Count: 1}}),
	)

	lat := s.LatencySeriesNs()
	lat[0] = 100
	if got := s.LatencySeriesNs()[0]; got != 1 {
		t.Fatalf("latency accessor leaked mutability: got %v", got)
	}

	syscalls := s.Syscalls()
	syscalls[0].Name = "write"
	if got := s.Syscalls()[0].Name; got != "read" {
		t.Fatalf("syscalls accessor leaked mutability: got %q", got)
	}

	buckets := s.LatencyHistogram.Buckets()
	buckets[0].Count = 99
	if got := s.LatencyHistogram.Buckets()[0].Count; got != 1 {
		t.Fatalf("bucket accessor leaked mutability: got %d", got)
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

	h := HistogramSnapshot{}
	if got := h.Buckets(); got != nil {
		t.Fatalf("expected nil buckets, got %#v", got)
	}
}
