package integrationtests

import (
	"strings"
	"syscall"
	"testing"

	iorparquet "ior/internal/parquet"
)

// The "path-faulted-names" scenario puts every path string on a page the
// workload has mapped but never touched, so the tracer's sys_enter nofault
// string read fails. Before the sys_exit recovery covered the pathname and name
// kinds, these rows carried an empty file: -path could not match them and the
// Files tab attributed them to ”. The scenario's syscalls are either failing
// (ENOENT) or renames, so the recovered name is the only evidence the capture
// worked.
var faultedPathTraceArgs = []string{"-trace-syscalls", "access,newfstatat,unlinkat,rename"}

func TestFaultedPathnamesAreRecoveredAtSysExit(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "path-faulted-names", defaultDuration, faultedPathTraceArgs, nil)
	enoent := ptrTo(-int64(syscall.ENOENT))
	AssertRowsPresent(t, rows, []ExpectedRow{
		{Syscall: "access", FileContains: "faulted-access-missing", RetVal: enoent, IsError: ptrTo(true)},
		{Syscall: "newfstatat", FileContains: "faulted-stat-missing", RetVal: enoent, IsError: ptrTo(true)},
		{Syscall: "unlinkat", FileContains: "faulted-unlink-missing", RetVal: enoent, IsError: ptrTo(true)},
	})
	for _, row := range rows {
		if row.Syscall != "rename" && row.File == "" {
			t.Errorf("%s row lost its file: %+v", row.Syscall, row)
		}
	}
}

// rename(old, new) can fault either name, both or neither; each recovery is
// independent, so each combination must keep its own old_file/file pair.
func TestFaultedRenameNamesAreRecoveredIndependently(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "path-faulted-names", defaultDuration, faultedPathTraceArgs, nil)
	for _, want := range []struct{ oldBase, newBase string }{
		{"faulted-both-old", "faulted-both-new"},
		{"faulted-oldonly-old", "touched-oldonly-new"},
		{"touched-newonly-old", "faulted-newonly-new"},
	} {
		if !hasRenameRow(rows, want.oldBase, want.newBase) {
			t.Errorf("no rename row with old_file ending %q and file ending %q", want.oldBase, want.newBase)
			logRowSummary(t, rows)
		}
	}
}

func hasRenameRow(rows []iorparquet.Record, oldBase, newBase string) bool {
	for _, row := range rows {
		if row.Syscall == "rename" && strings.HasSuffix(row.OldFile, "/"+oldBase) && strings.HasSuffix(row.File, "/"+newBase) {
			return true
		}
	}
	return false
}

// -path must match a row whose name only the exit-side re-read supplied, and
// must still drop the rows whose recovered names do not match: the enter gate
// defers the path dimension for a faulted read, it does not waive it.
func TestPathFilterMatchesFaultedNamesAfterRecovery(t *testing.T) {
	args := append([]string{"-path", "faulted-unlink-missing"}, faultedPathTraceArgs...)
	result, _ := runScenarioResultWithIorArgs(t, "path-faulted-names", []ExpectedEvent{
		{PathContains: "faulted-unlink-missing", Tracepoint: "enter_unlinkat", Comm: "ioworkload", MinCount: 1},
	}, args)
	AssertEventsAbsent(t, result, []ExpectedEvent{
		{PathContains: "faulted-access-missing"},
		{PathContains: "faulted-stat-missing"},
		{PathContains: "faulted-both-new"},
	})
}
