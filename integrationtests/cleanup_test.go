package integrationtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workloadTempDirPrefix is the prefix used by ioworkload's makeTempDir.
const workloadTempDirPrefix = "ioworkload-"

// snapshotWorkloadTempDirs returns a set of existing ioworkload temp dirs.
func snapshotWorkloadTempDirs(t *testing.T) map[string]struct{} {
	t.Helper()
	return listWorkloadTempDirs(t)
}

// listWorkloadTempDirs returns the set of ioworkload-* directories in the
// system temp directory.
func listWorkloadTempDirs(t *testing.T) map[string]struct{} {
	t.Helper()
	tmpDir := os.TempDir()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}

	dirs := make(map[string]struct{})
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), workloadTempDirPrefix) {
			dirs[filepath.Join(tmpDir, e.Name())] = struct{}{}
		}
	}
	return dirs
}

// assertNoNewWorkloadTempDirs fails if any new ioworkload temp dirs appeared
// since the snapshot was taken.
func assertNoNewWorkloadTempDirs(t *testing.T, before map[string]struct{}) {
	t.Helper()
	after := listWorkloadTempDirs(t)
	var leaked []string
	for dir := range after {
		if _, existed := before[dir]; !existed {
			leaked = append(leaked, dir)
		}
	}
	if len(leaked) > 0 {
		t.Errorf("leaked ioworkload temp dirs: %v", leaked)
		for _, dir := range leaked {
			os.RemoveAll(dir)
		}
	}
}

func TestCleanupOutputDirContainsOnlyExpectedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	// Fake workload that prints PID and exits cleanly.
	workloadBin := writeScript(t, tmpDir, "workload", `echo $$`)
	// Fake ior that creates an .ior.zst file and a .collapsed file.
	iorBin := writeScript(t, tmpDir, "ior",
		`touch test.ior.zst test.collapsed.zst test.svg`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	// Run returns error because the .ior.zst has no valid data, but that's fine;
	// we only care about what files ended up in OutputDir.
	h.Run("test", 5) //nolint:errcheck

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}

	// All files should be inside outputDir (which is t.TempDir(), auto-cleaned).
	for _, e := range entries {
		name := e.Name()
		validSuffix := strings.HasSuffix(name, ".ior.zst") ||
			strings.HasSuffix(name, ".collapsed.zst") ||
			strings.HasSuffix(name, ".svg") ||
			name == "ior.bpf.o" // symlink created by startIor
		if !validSuffix {
			t.Errorf("unexpected file in output dir: %s", name)
		}
	}
}

func TestCleanupNoWorkloadTempDirsLeakedOnSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	before := snapshotWorkloadTempDirs(t)

	// Fake workload that creates a temp dir, cleans it up, then exits.
	// This mimics the real ioworkload's makeTempDir + defer cleanup pattern.
	workloadBin := writeScript(t, tmpDir, "workload",
		`echo $$; d=$(mktemp -d /tmp/ioworkload-cleanup-test-XXXXXX); rm -rf "$d"`)
	iorBin := writeScript(t, tmpDir, "ior", `exit 0`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	h.Run("test", 5) //nolint:errcheck

	assertNoNewWorkloadTempDirs(t, before)
}

func TestCleanupNoWorkloadTempDirsLeakedOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	before := snapshotWorkloadTempDirs(t)

	// Fake workload that creates a temp dir, cleans it up, then exits with error.
	workloadBin := writeScript(t, tmpDir, "workload",
		`echo $$; d=$(mktemp -d /tmp/ioworkload-cleanup-test-XXXXXX); rm -rf "$d"; exit 1`)
	iorBin := writeScript(t, tmpDir, "ior", `exit 0`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	h.Run("test", 5) //nolint:errcheck

	assertNoNewWorkloadTempDirs(t, before)
}

func TestCleanupOutputDirEmptyAfterIorFailure(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	workloadBin := writeScript(t, tmpDir, "workload", `echo $$`)
	// Fake ior that fails without producing any output files.
	iorBin := writeScript(t, tmpDir, "ior", `exit 1`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	_, _, err := h.Run("test", 5)
	if err == nil {
		t.Fatal("expected error from ior failure, got nil")
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}

	// Only the BPF symlink should exist; ior produced no output.
	for _, e := range entries {
		if e.Name() != "ior.bpf.o" {
			t.Errorf("unexpected file in output dir after ior failure: %s", e.Name())
		}
	}
}

func TestCleanupDetectsLeakedWorkloadTempDir(t *testing.T) {
	before := snapshotWorkloadTempDirs(t)

	// Create a temp dir that looks like a leaked ioworkload dir.
	leaked, err := os.MkdirTemp("", workloadTempDirPrefix+"leak-test-")
	if err != nil {
		t.Fatalf("create leaked dir: %v", err)
	}
	defer os.RemoveAll(leaked)

	after := listWorkloadTempDirs(t)
	var found bool
	for dir := range after {
		if _, existed := before[dir]; !existed {
			found = true
			break
		}
	}
	if !found {
		t.Error("assertNoNewWorkloadTempDirs should detect the leaked dir")
	}
}

func TestCleanupNoArtifactsOutsideOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	// Fake workload that prints PID and exits.
	workloadBin := writeScript(t, tmpDir, "workload", `echo $$`)
	// Fake ior that creates output files only in its working directory (outputDir).
	iorBin := writeScript(t, tmpDir, "ior",
		`touch test.ior.zst`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	h.Run("test", 5) //nolint:errcheck

	// Verify no .ior.zst files were created in the test's tmpDir (script dir).
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read tmp dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ior.zst") ||
			strings.HasSuffix(e.Name(), ".collapsed") ||
			strings.HasSuffix(e.Name(), ".svg") {
			t.Errorf("artifact leaked to script dir: %s", e.Name())
		}
	}
}
