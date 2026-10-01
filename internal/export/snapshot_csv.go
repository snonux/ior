package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"ior/internal/atomicfile"
	"ior/internal/statsengine"
	"ior/internal/textsafe"
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
// and histograms, in that order. It is called only when snap is non-nil.
func writeSnapshotDetailRows(w *csv.Writer, snap *statsengine.Snapshot) error {
	sections := [][][]string{
		syscallRows(snap),
		fileRows(snap),
		processRows(snap),
		histogramRows("latency_hist", snap.LatencyHistogram),
		histogramRows("gap_hist", snap.GapHistogram),
	}
	for _, rows := range sections {
		if err := writeRows(w, rows); err != nil {
			return err
		}
	}
	return nil
}

// writeRows writes rows to w, stopping at the first error.
func writeRows(w *csv.Writer, rows [][]string) error {
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// syscallRows returns the count, latency and percentile rows of every
// syscall. The names come from ior's own syscall table, never traced text.
func syscallRows(snap *statsengine.Snapshot) [][]string {
	var rows [][]string
	for _, s := range snap.Syscalls() {
		rows = append(rows,
			[]string{"syscall", s.Name, fmt.Sprint(s.Count), fmt.Sprintf("%.2f", s.RatePerSec), fmt.Sprint(s.Bytes)},
			[]string{"syscall_latency_ns", s.Name, fmt.Sprintf("%.2f", s.LatencyMeanNs), fmt.Sprint(s.LatencyMinNs), fmt.Sprint(s.LatencyMaxNs)},
			[]string{"syscall_percentiles_ns", s.Name, fmt.Sprint(s.LatencyP50Ns), fmt.Sprint(s.LatencyP95Ns), fmt.Sprint(s.LatencyP99Ns)},
		)
	}
	return rows
}

// fileRows returns the access and latency rows of every ranked file.
//
// The file path is the only free-form traced text in the snapshot (the
// syscall names and histogram labels are ior's own, and the process column is
// a numeric id, not the comm). It goes through textsafe.SanitizePath, the
// repair the Parquet recording and the stream CSV export apply (tasks 3z2,
// 4z2): a rune cut at the BPF path capture limit is dropped and any other
// invalid UTF-8 byte becomes a \xHH escape, so a strict reader such as
// DuckDB's read_csv accepts the file. Valid text, including control
// characters, is kept as it is, and quotes, commas and newlines are left to
// the csv.Writer's quoting, so the file stays valid CSV.
func fileRows(snap *statsengine.Snapshot) [][]string {
	var rows [][]string
	for _, r := range snap.Files() {
		path := textsafe.SanitizePath(r.Path)
		rows = append(rows,
			[]string{"file", path, fmt.Sprint(r.Accesses), fmt.Sprint(r.BytesRead), fmt.Sprint(r.BytesWritten)},
			[]string{"file_latency_ns", path, fmt.Sprintf("%.2f", r.AvgLatencyNs), fmt.Sprint(r.MaxLatencyNs), ""},
		)
	}
	return rows
}

// processRows returns the syscall and latency rows of every process. A
// process row's id is ProcessSnapshot.ID: the bare PID, or "PID#n" for a
// later row of a recycled PID (n is a per-PID row number, which compaction of
// retired rows can renumber, not a count of processes), so the rows of one
// snapshot never share an id.
func processRows(snap *statsengine.Snapshot) [][]string {
	var rows [][]string
	for _, p := range snap.Processes() {
		rows = append(rows,
			[]string{"process", p.ID(), fmt.Sprint(p.Syscalls), fmt.Sprintf("%.2f", p.RatePerSec), fmt.Sprint(p.Bytes)},
			[]string{"process_latency_ns", p.ID(), fmt.Sprintf("%.2f", p.AvgLatencyNs), "", ""},
		)
	}
	return rows
}

// histogramRows returns one row per bucket of h under the given section name.
func histogramRows(section string, h statsengine.HistogramSnapshot) [][]string {
	var rows [][]string
	for _, b := range h.Buckets() {
		rows = append(rows, []string{section, b.Label, fmt.Sprint(b.Count), fmt.Sprint(b.LowerNs), fmt.Sprint(b.UpperNs)})
	}
	return rows
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
