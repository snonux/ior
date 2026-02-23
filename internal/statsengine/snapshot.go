package statsengine

import (
	"ior/internal/types"
	"slices"
	"time"
)

// TrendDirection is the direction of a time-window comparison.
type TrendDirection string

const (
	// TrendStable indicates no meaningful movement between windows.
	TrendStable TrendDirection = "stable"
	// TrendRising indicates the most recent window is higher than the previous one.
	TrendRising TrendDirection = "rising"
	// TrendFalling indicates the most recent window is lower than the previous one.
	TrendFalling TrendDirection = "falling"
)

// Trend describes movement between two equivalent time windows.
type Trend struct {
	Direction    TrendDirection
	DeltaPercent float64
}

// Snapshot is an immutable point-in-time view of all aggregated statistics.
type Snapshot struct {
	GeneratedAt time.Time
	Elapsed     time.Duration

	TotalSyscalls uint64
	TotalErrors   uint64
	TotalBytes    uint64

	SyscallRatePerSec float64
	ErrorRatePerSec   float64
	ReadBytesPerSec   float64
	WriteBytesPerSec  float64

	LatencyMeanNs float64
	GapMeanNs     float64

	LatencyTrend    Trend
	GapTrend        Trend
	ThroughputTrend Trend

	latencySeriesNs   []float64
	gapSeriesNs       []float64
	throughputSeriesB []float64

	syscalls  []SyscallSnapshot
	files     []FileSnapshot
	processes []ProcessSnapshot

	LatencyHistogram HistogramSnapshot
	GapHistogram     HistogramSnapshot
}

// SyscallSnapshot is the per-syscall view used by the syscall table.
type SyscallSnapshot struct {
	TraceID types.TraceId
	Name    string

	Count      uint64
	RatePerSec float64
	Errors     uint64
	Bytes      uint64

	LatencyMinNs  uint64
	LatencyMaxNs  uint64
	LatencyMeanNs float64
	LatencyP50Ns  uint64
	LatencyP95Ns  uint64
	LatencyP99Ns  uint64
}

// FileSnapshot is an aggregated per-file ranking entry.
type FileSnapshot struct {
	Path string

	Accesses     uint64
	BytesRead    uint64
	BytesWritten uint64

	AvgLatencyNs float64
	MaxLatencyNs uint64
}

// ProcessSnapshot is an aggregated per-process entry.
type ProcessSnapshot struct {
	PID  uint32
	Comm string

	Syscalls   uint64
	RatePerSec float64
	Bytes      uint64

	AvgLatencyNs float64
}

// HistogramBucketSnapshot is one bucket of a histogram snapshot.
type HistogramBucketSnapshot struct {
	Label   string
	LowerNs uint64
	UpperNs uint64
	Count   uint64
}

// HistogramSnapshot is an immutable histogram view at snapshot time.
type HistogramSnapshot struct {
	Total   uint64
	buckets []HistogramBucketSnapshot
}

// NewSnapshot creates a snapshot while defensively copying all slice-backed
// inputs so callers cannot mutate shared snapshot state.
func NewSnapshot(
	latencySeriesNs []float64,
	gapSeriesNs []float64,
	throughputSeriesB []float64,
	syscalls []SyscallSnapshot,
	files []FileSnapshot,
	processes []ProcessSnapshot,
	latencyHistogram HistogramSnapshot,
	gapHistogram HistogramSnapshot,
) Snapshot {
	return Snapshot{
		latencySeriesNs:   slices.Clone(latencySeriesNs),
		gapSeriesNs:       slices.Clone(gapSeriesNs),
		throughputSeriesB: slices.Clone(throughputSeriesB),
		syscalls:          slices.Clone(syscalls),
		files:             slices.Clone(files),
		processes:         slices.Clone(processes),
		LatencyHistogram:  latencyHistogram.Clone(),
		GapHistogram:      gapHistogram.Clone(),
	}
}

// NewHistogramSnapshot creates an immutable histogram snapshot by copying
// bucket storage.
func NewHistogramSnapshot(total uint64, buckets []HistogramBucketSnapshot) HistogramSnapshot {
	return HistogramSnapshot{
		Total:   total,
		buckets: slices.Clone(buckets),
	}
}

// Clone returns a deep copy of the histogram snapshot.
func (h HistogramSnapshot) Clone() HistogramSnapshot {
	return HistogramSnapshot{
		Total:   h.Total,
		buckets: slices.Clone(h.buckets),
	}
}

// LatencySeriesNs returns a defensive copy of latency sparkline samples.
func (s Snapshot) LatencySeriesNs() []float64 {
	return slices.Clone(s.latencySeriesNs)
}

// GapSeriesNs returns a defensive copy of inter-syscall gap sparkline samples.
func (s Snapshot) GapSeriesNs() []float64 {
	return slices.Clone(s.gapSeriesNs)
}

// ThroughputSeriesB returns a defensive copy of throughput sparkline samples.
func (s Snapshot) ThroughputSeriesB() []float64 {
	return slices.Clone(s.throughputSeriesB)
}

// Syscalls returns a defensive copy of per-syscall snapshot rows.
func (s Snapshot) Syscalls() []SyscallSnapshot {
	return slices.Clone(s.syscalls)
}

// Files returns a defensive copy of per-file snapshot rows.
func (s Snapshot) Files() []FileSnapshot {
	return slices.Clone(s.files)
}

// Processes returns a defensive copy of per-process snapshot rows.
func (s Snapshot) Processes() []ProcessSnapshot {
	return slices.Clone(s.processes)
}

// Buckets returns a defensive copy of histogram buckets.
func (h HistogramSnapshot) Buckets() []HistogramBucketSnapshot {
	return slices.Clone(h.buckets)
}
