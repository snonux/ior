package integrationtests

import (
	"strings"
	"syscall"
	"testing"

	iorparquet "ior/internal/parquet"
)

func TestFanotifyMarks(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "fanotify-marks", defaultDuration,
		[]string{"-trace-syscalls", "fanotify_init,fanotify_mark,openat,close"}, nil)
	groupFD := notificationGroupFD(t, rows, "fanotify_init")
	for _, target := range []string{"absolute", "relative", "null-target"} {
		var targetPath string
		for _, row := range rows {
			if row.Syscall == "openat" && strings.HasSuffix(row.File, "/"+target) && !row.IsError {
				targetPath = row.File
			}
		}
		if targetPath == "" {
			t.Fatalf("no successful open for fanotify target %s", target)
		}
		AssertRowsPresent(t, rows, []ExpectedRow{{Syscall: "fanotify_mark", FileContains: targetPath,
			FD: &groupFD, RetVal: ptrTo(int64(0)), IsError: ptrTo(false), Bytes: ptrTo(uint64(0))}})
	}
	AssertRowsPresent(t, rows, []ExpectedRow{
		{Syscall: "fanotify_mark", FileContains: "fanotifyfd:", FD: &groupFD, RetVal: ptrTo(int64(0)), IsError: ptrTo(false)},
		{Syscall: "fanotify_mark", FD: &groupFD, RetVal: ptrTo(-int64(syscall.ENOENT)), IsError: ptrTo(true)},
		{Syscall: "fanotify_mark", FD: &groupFD, RetVal: ptrTo(-int64(syscall.EBADF)), IsError: ptrTo(true)},
		{Syscall: "close", FileContains: "fanotifyfd:", FD: &groupFD, RetVal: ptrTo(int64(0)), IsError: ptrTo(false)},
	})
	for _, row := range rows {
		if row.Syscall != "fanotify_mark" {
			continue
		}
		if strings.Contains(row.File, "ignored-flush-target") {
			t.Error("FAN_MARK_FLUSH attributed to its ignored pathname")
		}
		if row.IsError && row.File != "" {
			t.Errorf("empty/invalid-NULL target acquired a pathname: %+v", row)
		}
	}
}

func notificationGroupFD(t *testing.T, rows []iorparquet.Record, syscallName string) int32 {
	t.Helper()
	for _, row := range rows {
		if row.Syscall == syscallName && !row.IsError && row.Ret >= 0 {
			if row.FD != int32(row.Ret) {
				t.Fatalf("group creation fd=%d ret=%d", row.FD, row.Ret)
			}
			return row.FD
		}
	}
	t.Fatalf("no successful %s group creation", syscallName)
	return -1
}
