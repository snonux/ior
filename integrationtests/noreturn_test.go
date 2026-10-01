package integrationtests

import (
	"encoding/json"
	"os"
	"testing"

	iorparquet "ior/internal/parquet"

	parquetgo "github.com/parquet-go/parquet-go"
)

// noreturnTraceArgs traces the three noreturn syscalls plus tgkill, the
// ordinary returning syscall the workload uses to raise its signals.
var noreturnTraceArgs = []string{
	"-trace-syscalls", "exit,exit_group,rt_sigreturn,tgkill",
}

// TestNoReturnSyscallsAreRows covers task pr2. exit, exit_group and
// rt_sigreturn never return, so no sys_exit record ever arrives for them;
// ior used to park their enters for good and a run selecting them produced
// no row at all. Each is now a row at enter, with no return value and no
// latency (ret 0, latency_ns 0, is_error false in Parquet):
//   - exit_group exactly once, from the main thread (tid == pid), when the
//     workload returns from main - recorded although that very exit ends the
//     -pid run;
//   - exit exactly once, from the one non-main thread the scenario ends;
//   - rt_sigreturn at least once per handled SIGUSR1.
//
// tgkill is the negative control: a returning syscall in the same run still
// pairs enter with exit, so it keeps a measured latency.
func TestNoReturnSyscallsAreRows(t *testing.T) {
	rows, pid := runParquetScenarioRows(t, "noreturn-syscalls", defaultDuration,
		noreturnTraceArgs, []string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})

	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Syscall]++
		switch row.Syscall {
		case "exit", "exit_group", "rt_sigreturn":
			assertNoReturnRecord(t, row)
		case "tgkill":
			if row.LatencyNS == 0 || row.Ret != 0 {
				t.Errorf("tgkill row latency=%d ret=%d, want a measured latency and ret 0", row.LatencyNS, row.Ret)
			}
		}
		if row.Syscall == "exit_group" && row.TID != uint32(pid) {
			t.Errorf("exit_group row tid = %d, want the main thread %d", row.TID, pid)
		}
		if row.Syscall == "exit" && row.TID == uint32(pid) {
			t.Errorf("exit row came from the main thread %d, want the ended worker thread", pid)
		}
	}

	if counts["exit_group"] != 1 || counts["exit"] != 1 {
		t.Errorf("exit_group rows = %d, exit rows = %d, want exactly 1 each (counts %v)",
			counts["exit_group"], counts["exit"], counts)
	}
	if counts["rt_sigreturn"] < 3 || counts["tgkill"] < 3 {
		t.Errorf("rt_sigreturn rows = %d, tgkill rows = %d, want at least 3 each (counts %v)",
			counts["rt_sigreturn"], counts["tgkill"], counts)
	}
}

// assertNoReturnRecord checks the persisted shape of a noreturn row: neither
// a return value nor a latency, and never an error.
func assertNoReturnRecord(t *testing.T, row iorparquet.Record) {
	t.Helper()
	if row.Ret != 0 || row.LatencyNS != 0 || row.IsError {
		t.Errorf("%s row ret=%d latency=%d is_error=%v, want 0/0/false",
			row.Syscall, row.Ret, row.LatencyNS, row.IsError)
	}
}

// TestAggregateOnlyNoReturnSyscallsAreCounted covers the kernel half of task
// pr2. An aggregate-only noreturn syscall emits no row, and since it never
// reaches sys_exit - where every other syscall is counted into the kernel
// aggregate - it used to be counted nowhere: the Parquet footer's exact
// sampling totals showed no rt_sigreturn calls at all. The noreturn enter hook
// now counts it untimed at enter.
func TestAggregateOnlyNoReturnSyscallsAreCounted(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	h.WorkloadEnv = []string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"}
	args := append(append([]string(nil), noreturnTraceArgs...),
		"-syscall-sampling-syscalls", "rt_sigreturn=0")
	path, pid, err := h.RunParquetWithIorArgs("noreturn-syscalls", defaultDuration, args)
	if err != nil {
		t.Fatalf("run parquet scenario noreturn-syscalls: %v", err)
	}
	rows := readParquetRecords(t, path)
	assertParquetRowsOwnedBy(t, rows, uint32(pid), "ioworkload")
	for _, row := range rows {
		if row.Syscall == "rt_sigreturn" {
			t.Fatalf("aggregate-only rt_sigreturn produced a row: %+v", row)
		}
	}

	var totals []struct {
		Syscall string `json:"syscall"`
		Traced  uint64 `json:"traced"`
		Counted uint64 `json:"counted_only"`
	}
	raw := parquetFooterValue(t, path, iorparquet.KeySamplingTotals)
	if err := json.Unmarshal([]byte(raw), &totals); err != nil {
		t.Fatalf("decode %s %q: %v", iorparquet.KeySamplingTotals, raw, err)
	}
	for _, entry := range totals {
		if entry.Syscall == "rt_sigreturn" {
			if entry.Traced != 0 || entry.Counted < 3 {
				t.Fatalf("rt_sigreturn totals = %+v, want 0 traced and at least 3 counted only", entry)
			}
			return
		}
	}
	t.Fatalf("%s %s has no rt_sigreturn entry", iorparquet.KeySamplingTotals, raw)
}

// parquetFooterValue returns the footer key/value entry key of the Parquet
// file at path, failing the test when it is missing.
func parquetFooterValue(t *testing.T, path, key string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	file, err := parquetgo.OpenFile(f, info.Size())
	if err != nil {
		t.Fatalf("open parquet %s: %v", path, err)
	}
	value, ok := file.Lookup(key)
	if !ok {
		t.Fatalf("parquet footer of %s has no %s", path, key)
	}
	return value
}
