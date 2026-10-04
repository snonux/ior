package statsengine

import (
	"slices"
	"strconv"
	"time"

	"ior/internal/types"
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

	TotalSyscalls          uint64
	TotalErrors            uint64
	TotalBytes             uint64
	TotalAddressSpaceBytes uint64

	SyscallRatePerSec       float64
	ErrorRatePerSec         float64
	AddressSpaceBytesPerSec float64
	ReadBytesPerSec         float64
	WriteBytesPerSec        float64

	LatencyMeanNs float64
	// GapMeanNs is the mean gap between consecutive traced calls on a
	// thread, over the same samples as GapHistogram and GapSeriesNs (a
	// thread's first traced call has no gap and is left out). Under sampling,
	// or for syscalls counted only in kernel aggregate rows, a gap spans the
	// untraced calls in between, so it is not a per-call gap (see
	// tracedGapMean).
	GapMeanNs float64

	LatencyTrend    Trend
	GapTrend        Trend
	ThroughputTrend Trend

	latencySeriesNs   []float64
	gapSeriesNs       []float64
	throughputSeriesB []float64

	syscalls  []SyscallSnapshot
	files     []FileSnapshot
	processes []ProcessSnapshot

	// dirs and otherDirs are the engine's own per-directory ranking (see
	// WithDirs); hasDirs tells a snapshot carrying it - possibly with no
	// rows - from one built without it, whose Dirs fall back to grouping
	// files.
	dirs      []DirSnapshot
	otherDirs DirSnapshot
	hasDirs   bool

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

	LatencyMinNs   uint64
	LatencyMaxNs   uint64
	LatencyMeanNs  float64
	TotalLatencyNs uint64
	LatencyP50Ns   uint64
	LatencyP95Ns   uint64
	LatencyP99Ns   uint64
	// NoLatency reports that none of Count carried a latency: every
	// invocation was untimed (noreturn rows of exit, exit_group and
	// rt_sigreturn, which never reach sys_exit; kernel aggregate counts
	// without a duration, see SyscallAggregate.UntimedCount). The latency
	// fields above are then 0 placeholders, not a measured 0ns, and the
	// views show "-" for them. It is the negation of "has a timed sample"
	// so that a literal SyscallSnapshot (test fixtures, -testflames) keeps
	// showing its latencies.
	NoLatency bool
	// NoPercentiles reports that LatencyP50/95/99Ns are 0 placeholders: the
	// percentile reservoir holds no latency sample for this syscall. A kernel
	// aggregate row (a syscall at sampling rate 0, e.g. futex) has a timed
	// mean/min/max from the BPF aggregate but no per-invocation samples, so
	// its percentiles are unknown, not 0ns, and the views show "-" for them
	// (task 003). Like NoLatency it is a negative flag so a literal
	// SyscallSnapshot keeps showing the percentiles it carries.
	NoPercentiles bool
}

// NoPercentileData reports whether the percentile cells have nothing to show:
// the row has no timed invocation at all, or no sample behind its percentiles.
func (s SyscallSnapshot) NoPercentileData() bool {
	return s.NoLatency || s.NoPercentiles
}

// FileSnapshot is an aggregated per-file ranking entry.
type FileSnapshot struct {
	Path string

	Accesses     uint64
	BytesRead    uint64
	BytesWritten uint64

	AvgLatencyNs   float64
	MaxLatencyNs   uint64
	TotalLatencyNs uint64
}

// DirSnapshot is one aggregated directory row of the Files tab's dir-grouped
// view: the counters of every file whose DirOf is Dir. Engine snapshots build
// it from all ranked traffic, not only the top-N files.
type DirSnapshot struct {
	Dir string

	Accesses     uint64
	BytesRead    uint64
	BytesWritten uint64

	AvgLatencyNs   float64
	MaxLatencyNs   uint64
	TotalLatencyNs uint64
	// FileCount is the number of distinct files seen in the directory:
	// exact up to a few hundred, a ~6% estimate beyond (see fileSketch). On
	// the remainder row it sums its directories' counts.
	FileCount uint64

	// Folded is the number of directories summed into this row. It is zero
	// for a real directory row and non-zero only for the remainder ("other")
	// row of Snapshot.DirsOther, whose Dir is empty. A directory that was
	// dropped by the ranker's cardinality guard and later reappeared counts
	// once per stay, so Folded can exceed the true number of directories.
	Folded uint64
}

// IsRemainder reports whether the row is the remainder row summing the
// directories outside the top-N rather than one directory.
func (d DirSnapshot) IsRemainder() bool {
	return d.Folded > 0
}

// ProcessSnapshot is an aggregated per-process entry: one process lifetime.
// A PID the kernel recycled during the session appears once per lifetime,
// each row with its own counts and comm.
type ProcessSnapshot struct {
	PID uint32
	// Lifetime is a per-PID row number that tells apart the rows of one PID
	// (it is not a count of recycled processes): 0 for the first row of the
	// PID, counting up with each row retired before it (see
	// Engine.RetireProcess). Compaction of the retired rows (keepOnly) can
	// renumber the survivors, so a still-running process may get a different
	// number, or restart at 0, after one; within one snapshot the ID is
	// unique, which is all it promises. Engine.Reset clears the rows but a
	// process that is still running reappears with the same Lifetime.
	Lifetime uint32
	Comm     string

	Syscalls   uint64
	RatePerSec float64
	Bytes      uint64

	AvgLatencyNs   float64
	TotalLatencyNs uint64
	// NoLatency reports that none of Syscalls carried a latency (all of
	// them were noreturn rows, e.g. a process seen only at its exit_group),
	// so AvgLatencyNs is a 0 placeholder that the views show as "-". See
	// SyscallSnapshot.NoLatency.
	NoLatency bool
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

// WithDirs returns a copy of the snapshot carrying the given per-directory
// ranking: the top-N rows (accesses descending) and the remainder row summing
// every directory outside them (zero-valued, Folded == 0, when there is
// none). The slices are copied.
func (s Snapshot) WithDirs(dirs []DirSnapshot, other DirSnapshot) Snapshot {
	s.dirs = slices.Clone(dirs)
	s.otherDirs = other
	s.hasDirs = true
	return s
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

// LatencySeriesNs returns latency sparkline samples.
// Callers must treat returned data as read-only.
func (s Snapshot) LatencySeriesNs() []float64 {
	return s.latencySeriesNs
}

// GapSeriesNs returns inter-syscall gap sparkline samples.
// Callers must treat returned data as read-only.
func (s Snapshot) GapSeriesNs() []float64 {
	return s.gapSeriesNs
}

// ThroughputSeriesB returns throughput sparkline samples.
// Callers must treat returned data as read-only.
func (s Snapshot) ThroughputSeriesB() []float64 {
	return s.throughputSeriesB
}

// Syscalls returns per-syscall snapshot rows.
// Callers must treat returned data as read-only.
func (s Snapshot) Syscalls() []SyscallSnapshot {
	return s.syscalls
}

// SyscallsCount returns number of syscall rows without cloning backing slices.
func (s Snapshot) SyscallsCount() int {
	return len(s.syscalls)
}

// TopNSyscalls returns at most n per-syscall rows in ranking order.
// Callers must treat returned data as read-only.
func (s Snapshot) TopNSyscalls(n int) []SyscallSnapshot {
	return topN(s.syscalls, n)
}

// Files returns per-file snapshot rows.
// Callers must treat returned data as read-only.
func (s Snapshot) Files() []FileSnapshot {
	return s.files
}

// FilesCount returns number of file rows without cloning backing slices.
func (s Snapshot) FilesCount() int {
	return len(s.files)
}

// TopNFiles returns at most n file rows in ranking order.
// Callers must treat returned data as read-only.
func (s Snapshot) TopNFiles(n int) []FileSnapshot {
	return topN(s.files, n)
}

// Processes returns per-process snapshot rows.
// Callers must treat returned data as read-only.
func (s Snapshot) Processes() []ProcessSnapshot {
	return s.processes
}

// Dirs returns the per-directory rows, accesses descending then directory.
// An engine snapshot ranks directories over ALL traffic (bounded top-N, the
// rest in DirsOther), so a directory holding thousands of once-read files
// appears even though none of them is in Files. A snapshot built without
// directory rows (NewSnapshot alone) falls back to grouping Files, which can
// only see those files.
// Callers must treat returned data as read-only.
func (s Snapshot) Dirs() []DirSnapshot {
	if s.hasDirs {
		return s.dirs
	}
	return AggregateFilesByDir(s.files)
}

// DirsOther returns the remainder row summing every directory that is not in
// Dirs, and false when there is none (always so for a snapshot without
// engine-provided directory rows).
func (s Snapshot) DirsOther() (DirSnapshot, bool) {
	return s.otherDirs, s.otherDirs.IsRemainder()
}

// ProcessesCount returns number of process rows without cloning backing slices.
func (s Snapshot) ProcessesCount() int {
	return len(s.processes)
}

// TopNProcesses returns at most n process rows in ranking order.
// Callers must treat returned data as read-only.
func (s Snapshot) TopNProcesses(n int) []ProcessSnapshot {
	return topN(s.processes, n)
}

// Buckets returns histogram buckets.
// Callers must treat returned data as read-only.
func (h HistogramSnapshot) Buckets() []HistogramBucketSnapshot {
	return h.buckets
}

func topN[T any](rows []T, n int) []T {
	if n <= 0 || len(rows) == 0 {
		return nil
	}
	if n > len(rows) {
		n = len(rows)
	}
	return rows[:n:n]
}

// ID returns the row's process identity as shown to users: the bare PID for
// the first lifetime, "PID#lifetime" for a later process that was handed the
// same PID (e.g. "2000#1"). It tells apart the rows of a recycled PID in the
// TUI and in exports while leaving the common, never-recycled case unchanged.
func (p ProcessSnapshot) ID() string {
	return ProcessID(p.PID, p.Lifetime)
}

// ProcessID formats a process identity the way ProcessSnapshot.ID does.
func ProcessID(pid, lifetime uint32) string {
	id := strconv.FormatUint(uint64(pid), 10)
	if lifetime == 0 {
		return id
	}
	return id + "#" + strconv.FormatUint(uint64(lifetime), 10)
}
