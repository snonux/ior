package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"ior/internal/atomicfile"
	"ior/internal/statsengine"
)

// SnapshotCSV writes a dashboard snapshot to a timestamped CSV file in the
// working directory and returns the name it was written under.
//
// The timestamp is accurate to the second, so two snapshots in the same second
// compute the same name. The file is built in a uniquely named temp file and
// published without replacing anything, so the later snapshot gets a "-N"
// suffix instead of overwriting (or writing through a symlink planted at) the
// earlier one.
func SnapshotCSV(snap *statsengine.Snapshot) (string, error) {
	name := fmt.Sprintf("ior-snapshot-%s.csv", time.Now().Format("20060102-150405"))
	return atomicfile.WriteFile(name, ".csv", func(out io.Writer) error {
		w := csv.NewWriter(out)
		if err := writeSnapshotRows(w, snap); err != nil {
			return err
		}
		w.Flush()
		return w.Error()
	})
}

// writeSnapshotRows writes all CSV sections to w in order:
// header, summary, per-syscall stats, file stats, process stats, histograms.
func writeSnapshotRows(w *csv.Writer, snap *statsengine.Snapshot) error {
	summaryRows := [][]string{
		{"section", "name", "value1", "value2", "value3"},
		{"summary", "totals",
			fmt.Sprint(snapValue(snap, func(s *statsengine.Snapshot) uint64 { return s.TotalSyscalls })),
			fmt.Sprint(snapValue(snap, func(s *statsengine.Snapshot) uint64 { return s.TotalErrors })),
			fmt.Sprint(snapValue(snap, func(s *statsengine.Snapshot) uint64 { return s.TotalBytes }))},
		{"summary", "rates_per_sec",
			fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.SyscallRatePerSec })),
			fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.ReadBytesPerSec })),
			fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.WriteBytesPerSec }))},
		{"summary", "latency_gap_mean_ns",
			fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.LatencyMeanNs })),
			fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.GapMeanNs })), ""},
		{"summary", "trend",
			trendSummary(snap, func(s *statsengine.Snapshot) statsengine.Trend { return s.LatencyTrend }),
			trendSummary(snap, func(s *statsengine.Snapshot) statsengine.Trend { return s.GapTrend }),
			trendSummary(snap, func(s *statsengine.Snapshot) statsengine.Trend { return s.ThroughputTrend })},
	}
	for _, row := range summaryRows {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	if snap == nil {
		return nil
	}
	return writeSnapshotDetailRows(w, snap)
}

// writeSnapshotDetailRows writes per-item rows for syscalls, files, processes,
// and histograms. It is called only when snap is non-nil.
func writeSnapshotDetailRows(w *csv.Writer, snap *statsengine.Snapshot) error {
	for _, s := range snap.Syscalls() {
		if err := w.Write([]string{"syscall", s.Name, fmt.Sprint(s.Count), fmt.Sprintf("%.2f", s.RatePerSec), fmt.Sprint(s.Bytes)}); err != nil {
			return err
		}
		if err := w.Write([]string{"syscall_latency_ns", s.Name, fmt.Sprintf("%.2f", s.LatencyMeanNs), fmt.Sprint(s.LatencyMinNs), fmt.Sprint(s.LatencyMaxNs)}); err != nil {
			return err
		}
		if err := w.Write([]string{"syscall_percentiles_ns", s.Name, fmt.Sprint(s.LatencyP50Ns), fmt.Sprint(s.LatencyP95Ns), fmt.Sprint(s.LatencyP99Ns)}); err != nil {
			return err
		}
	}
	for _, r := range snap.Files() {
		if err := w.Write([]string{"file", r.Path, fmt.Sprint(r.Accesses), fmt.Sprint(r.BytesRead), fmt.Sprint(r.BytesWritten)}); err != nil {
			return err
		}
		if err := w.Write([]string{"file_latency_ns", r.Path, fmt.Sprintf("%.2f", r.AvgLatencyNs), fmt.Sprint(r.MaxLatencyNs), ""}); err != nil {
			return err
		}
	}
	// A process row's id is ProcessSnapshot.ID: the bare PID, or "PID#n"
	// for the n-th later process the kernel handed a recycled PID, so the
	// rows of distinct processes never share an id.
	for _, p := range snap.Processes() {
		if err := w.Write([]string{"process", p.ID(), fmt.Sprint(p.Syscalls), fmt.Sprintf("%.2f", p.RatePerSec), fmt.Sprint(p.Bytes)}); err != nil {
			return err
		}
		if err := w.Write([]string{"process_latency_ns", p.ID(), fmt.Sprintf("%.2f", p.AvgLatencyNs), "", ""}); err != nil {
			return err
		}
	}
	for _, b := range snap.LatencyHistogram.Buckets() {
		if err := w.Write([]string{"latency_hist", b.Label, fmt.Sprint(b.Count), fmt.Sprint(b.LowerNs), fmt.Sprint(b.UpperNs)}); err != nil {
			return err
		}
	}
	for _, b := range snap.GapHistogram.Buckets() {
		if err := w.Write([]string{"gap_hist", b.Label, fmt.Sprint(b.Count), fmt.Sprint(b.LowerNs), fmt.Sprint(b.UpperNs)}); err != nil {
			return err
		}
	}
	return nil
}

func snapValue(snap *statsengine.Snapshot, get func(*statsengine.Snapshot) uint64) uint64 {
	if snap == nil {
		return 0
	}
	return get(snap)
}

func snapValueF(snap *statsengine.Snapshot, get func(*statsengine.Snapshot) float64) float64 {
	if snap == nil {
		return 0
	}
	return get(snap)
}

func trendSummary(snap *statsengine.Snapshot, get func(*statsengine.Snapshot) statsengine.Trend) string {
	if snap == nil {
		return "stable:0.00"
	}
	trend := get(snap)
	return fmt.Sprintf("%s:%.2f", trend.Direction, trend.DeltaPercent)
}
