package integrationtests

import (
	"strings"
	"testing"
)

func TestRenameBasic(t *testing.T) {
	runScenario(t, "rename-basic", []ExpectedEvent{
		{
			PathContains: "newname.txt",
			Tracepoint:   "enter_rename",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameRenameat(t *testing.T) {
	runScenario(t, "rename-renameat", []ExpectedEvent{
		{
			PathContains: "renameat-new.txt",
			Tracepoint:   "enter_renameat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameRenameat2(t *testing.T) {
	runScenario(t, "rename-renameat2", []ExpectedEvent{
		{
			PathContains: "renameat2-new.txt",
			Tracepoint:   "enter_renameat2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameEnoent(t *testing.T) {
	runScenario(t, "rename-enoent", []ExpectedEvent{
		{
			PathContains: "rename-enoent-new.txt",
			Tracepoint:   "enter_rename",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameNoreplace(t *testing.T) {
	runScenario(t, "rename-noreplace", []ExpectedEvent{
		{
			PathContains: "noreplace-dst.txt",
			Tracepoint:   "enter_renameat2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

// TestRenameRenameatOldnameInParquet locks in the oldname capture end-to-end
// for an AT-variant. renameat passes the source path at args[1] (after the
// olddfd dirfd), so this validates the args[1] oldname index: the new `old_file`
// parquet column must carry the source path while `file` carries the new path.
// A wrong-oldname-index regression would surface here as a missing/empty
// old_file, which no prior persisted-output test could detect.
func TestRenameRenameatOldnameInParquet(t *testing.T) {
	h := newTestHarness(t)
	path, pid, err := h.RunParquetWithIorArgs("rename-renameat", defaultDuration,
		[]string{"-trace-syscalls", "renameat"})
	if err != nil {
		t.Fatalf("run rename-renameat parquet scenario: %v", err)
	}

	rows := filterRecordsByPID(readParquetRecords(t, path), uint32(pid))
	if len(rows) == 0 {
		t.Fatalf("expected parquet rows for workload PID %d", pid)
	}

	var sawRenameat bool
	for _, row := range rows {
		if row.Syscall != "renameat" {
			// old_file is rename/link-only; everything else must leave it empty.
			if row.OldFile != "" {
				t.Fatalf("%s row has unexpected old_file %q", row.Syscall, row.OldFile)
			}
			continue
		}
		sawRenameat = true
		// file == newname; old_file == oldname (captured at args[1]).
		if !strings.Contains(row.File, "renameat-new.txt") {
			t.Fatalf("renameat row file = %q, want it to contain renameat-new.txt", row.File)
		}
		if !strings.Contains(row.OldFile, "renameat-old.txt") {
			t.Fatalf("renameat row old_file = %q, want it to contain renameat-old.txt (args[1] oldname capture)", row.OldFile)
		}
	}

	if !sawRenameat {
		t.Fatalf("expected at least one renameat row in parquet output")
	}
}
