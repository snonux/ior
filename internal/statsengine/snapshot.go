package statsengine

import (
	"ior/internal/types"
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

	LatencySeriesNs   []float64
	GapSeriesNs       []float64
	ThroughputSeriesB []float64

	Syscalls  []SyscallSnapshot
	Files     []FileSnapshot
	Processes []ProcessSnapshot

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
	Buckets []HistogramBucketSnapshot
}
