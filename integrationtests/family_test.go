package integrationtests

import (
	"io"
	"os"
	"testing"

	iorparquet "ior/internal/parquet"

	parquetgo "github.com/parquet-go/parquet-go"
)

const (
	familyParquetDuration    = 6
	familyWorkloadStartupEnv = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
)

var familyMixedTraceArgs = []string{"-trace-syscalls", "openat,write,mmap,munmap,pipe2,socketpair,getpid,sched_yield,nanosleep"}

func TestFamilyParquetRecordingAndAggregation(t *testing.T) {
	h := newTestHarness(t)
	h.WorkloadEnv = []string{familyWorkloadStartupEnv}
	path, pid, err := h.RunParquetWithIorArgs("family-mixed", familyParquetDuration, familyMixedTraceArgs)
	if err != nil {
		t.Fatalf("run family-mixed parquet scenario: %v", err)
	}

	rows := filterRecordsByPID(readParquetRecords(t, path), uint32(pid))
	if len(rows) == 0 {
		t.Fatalf("expected parquet rows for workload PID %d", pid)
	}

	expectedSyscallFamilies := map[string]string{
		"openat":      "FS",
		"write":       "FS",
		"mmap":        "Memory",
		"munmap":      "Memory",
		"pipe2":       "IPC",
		"socketpair":  "Network",
		"getpid":      "Process",
		"sched_yield": "Sched",
	}
	seenSyscalls := make(map[string]bool, len(expectedSyscallFamilies))
	for _, row := range rows {
		if row.Family == "" {
			t.Fatalf("record has empty family tag: %+v", row)
		}
		wantFamily, ok := expectedSyscallFamilies[row.Syscall]
		if !ok {
			continue
		}
		if row.Family != wantFamily {
			t.Fatalf("%s family = %q, want %q in row %+v", row.Syscall, row.Family, wantFamily, row)
		}
		seenSyscalls[row.Syscall] = true
	}
	for syscall := range expectedSyscallFamilies {
		if !seenSyscalls[syscall] {
			t.Fatalf("expected traced syscall %q in parquet rows; saw syscalls: %+v", syscall, seenSyscalls)
		}
	}

	families := aggregateRecordedFamilies(rows)
	var total uint64
	for _, count := range families {
		total += count
	}
	if total != uint64(len(rows)) {
		t.Fatalf("aggregated family total = %d, want row count %d", total, len(rows))
	}
	for _, family := range []string{"FS", "Memory", "IPC", "Network", "Process", "Sched", "Time"} {
		if families[family] == 0 {
			t.Fatalf("expected family %q in aggregate counts, got %+v", family, families)
		}
	}
}

func filterRecordsByPID(rows []iorparquet.Record, pid uint32) []iorparquet.Record {
	filtered := make([]iorparquet.Record, 0, len(rows))
	for _, row := range rows {
		if row.PID == pid {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func readParquetRecords(t *testing.T, path string) []iorparquet.Record {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open parquet %q: %v", path, err)
	}
	defer f.Close()

	reader := parquetgo.NewGenericReader[iorparquet.Record](f)
	defer reader.Close()

	var rows []iorparquet.Record
	buf := make([]iorparquet.Record, 16)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			rows = append(rows, buf[:n]...)
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			return rows
		}
		t.Fatalf("read parquet rows: %v", err)
	}
}

func aggregateRecordedFamilies(rows []iorparquet.Record) map[string]uint64 {
	families := make(map[string]uint64)
	for _, row := range rows {
		families[row.Family]++
	}
	return families
}
