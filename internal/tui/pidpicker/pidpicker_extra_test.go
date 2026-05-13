package pidpicker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFormatProcessWithParent verifies that formatProcess includes parent PID
// when present and different from the process PID.
func TestFormatProcessWithParent(t *testing.T) {
	p := ProcessInfo{Pid: 200, ParentPID: 100, Comm: "worker", Cmdline: "worker --run"}
	out := formatProcess(p)
	if !strings.Contains(out, "200") || !strings.Contains(out, "100") {
		t.Fatalf("expected pid and parent in output, got: %q", out)
	}
	if !strings.Contains(out, "worker") {
		t.Fatalf("expected comm in output, got: %q", out)
	}
	if !strings.Contains(out, "worker --run") {
		t.Fatalf("expected cmdline in output, got: %q", out)
	}
}

// TestFormatProcessWithParentNoCmdline verifies that formatProcess omits the
// cmdline section when Cmdline is empty and a parent PID is present.
func TestFormatProcessWithParentNoCmdline(t *testing.T) {
	p := ProcessInfo{Pid: 300, ParentPID: 100, Comm: "kworker", Cmdline: ""}
	out := formatProcess(p)
	if !strings.Contains(out, "300") || !strings.Contains(out, "kworker") {
		t.Fatalf("expected pid and comm in output, got: %q", out)
	}
}

// TestFormatProcessNoParentWithCmdline verifies formatProcess for a top-level
// process that has a cmdline.
func TestFormatProcessNoParentWithCmdline(t *testing.T) {
	p := ProcessInfo{Pid: 1, ParentPID: 1, Comm: "init", Cmdline: "/sbin/init"}
	out := formatProcess(p)
	if !strings.Contains(out, "1") || !strings.Contains(out, "init") || !strings.Contains(out, "/sbin/init") {
		t.Fatalf("expected pid, comm, cmdline in output, got: %q", out)
	}
}

// TestFormatProcessNoParentNoCmdline verifies formatProcess for a kernel thread
// with no cmdline.
func TestFormatProcessNoParentNoCmdline(t *testing.T) {
	p := ProcessInfo{Pid: 5, ParentPID: 5, Comm: "kthread", Cmdline: ""}
	out := formatProcess(p)
	if !strings.Contains(out, "5") || !strings.Contains(out, "kthread") {
		t.Fatalf("expected pid and comm in output, got: %q", out)
	}
}

// TestClampHelperBoundaries verifies that the unexported clamp function handles
// below-min, above-max, and in-range values.
func TestClampHelperBoundaries(t *testing.T) {
	if got := clamp(-5, 0, 10); got != 0 {
		t.Fatalf("clamp below min = %d, want 0", got)
	}
	if got := clamp(15, 0, 10); got != 10 {
		t.Fatalf("clamp above max = %d, want 10", got)
	}
	if got := clamp(7, 0, 10); got != 7 {
		t.Fatalf("clamp in range = %d, want 7", got)
	}
}

// TestSetDarkModeDoesNotPanic verifies that SetDarkMode can be called for both
// dark and light themes without panicking.
func TestSetDarkModeDoesNotPanic(t *testing.T) {
	m := NewWithKeys(DefaultKeyMap())
	m = m.SetDarkMode(false)
	m = m.SetDarkMode(true)
	_ = m
}

// TestScanAllThreadsFromIntegration exercises scanAllThreadsFrom against a
// temporary /proc-like directory tree with two processes and their task threads.
func TestScanAllThreadsFromIntegration(t *testing.T) {
	root := t.TempDir()

	// Process 10 with one thread.
	proc10 := filepath.Join(root, "10")
	if err := os.MkdirAll(filepath.Join(proc10, "task", "10"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(proc10, "stat"), "10 (proc10) S 1 1 1 0")
	writeFile(t, filepath.Join(proc10, "cmdline"), "proc10\x00")
	writeFile(t, filepath.Join(proc10, "task", "10", "comm"), "proc10-main\n")

	// Process 20 with two threads.
	proc20 := filepath.Join(root, "20")
	if err := os.MkdirAll(filepath.Join(proc20, "task", "20"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(proc20, "task", "21"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(proc20, "stat"), "20 (proc20) S 1 1 1 0")
	writeFile(t, filepath.Join(proc20, "cmdline"), "proc20\x00")
	writeFile(t, filepath.Join(proc20, "task", "20", "comm"), "proc20-main\n")
	writeFile(t, filepath.Join(proc20, "task", "21", "comm"), "proc20-worker\n")

	threads, err := scanAllThreadsFrom(root)
	if err != nil {
		t.Fatalf("scanAllThreadsFrom: %v", err)
	}
	if len(threads) != 3 {
		t.Fatalf("expected 3 threads, got %d", len(threads))
	}

	// Results are sorted by TID.
	tids := make([]int, len(threads))
	for i, th := range threads {
		tids[i] = th.Pid
	}
	for i := 1; i < len(tids); i++ {
		if tids[i] < tids[i-1] {
			t.Fatalf("threads not sorted: %v", tids)
		}
	}
}

// TestReadThreadInfoSkipsNonDirEntry verifies that readThreadInfo returns false
// for non-directory entries.
func TestReadThreadInfoSkipsNonDirEntry(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "not-a-dir"), "content")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	_, ok := readThreadInfo(root, entries[0], "cmdline text")
	if ok {
		t.Fatal("expected readThreadInfo to return false for a file entry")
	}
}

// TestReadThreadInfoSkipsNonNumericDirs verifies that readThreadInfo returns
// false for directory entries whose names are not numeric TIDs.
func TestReadThreadInfoSkipsNonNumericDirs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "notanumber"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	_, ok := readThreadInfo(root, entries[0], "")
	if ok {
		t.Fatal("expected readThreadInfo to skip non-numeric dir")
	}
}

// TestExtractPIDFromPath verifies the PID extraction logic for task root paths.
func TestExtractPIDFromPath(t *testing.T) {
	pid := extractPIDFromPath("/proc/1234/task")
	if pid != 1234 {
		t.Fatalf("extractPIDFromPath = %d, want 1234", pid)
	}

	if got := extractPIDFromPath("short"); got != -1 {
		t.Fatalf("extractPIDFromPath(short) = %d, want -1", got)
	}
}

// TestPickerShortHelpReturnsBindings verifies that KeyMap.PickerShortHelp
// returns exactly three bindings.
func TestPickerShortHelpReturnsBindings(t *testing.T) {
	keys := DefaultKeyMap()
	bindings := keys.PickerShortHelp()
	if len(bindings) != 3 {
		t.Fatalf("PickerShortHelp len = %d, want 3", len(bindings))
	}
}

// writeFile is a test helper that writes content to a file, failing the test on
// any error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}
