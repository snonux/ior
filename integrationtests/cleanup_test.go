package integrationtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workloadTempDirPrefix is the prefix used by ioworkload's makeTempDir.
const workloadTempDirPrefix = "ioworkload-"

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
// since the snapshot was taken. It also cleans up any leaked dirs to prevent
// cascading failures in subsequent tests.
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

	workloadBin := writeScript(t, tmpDir, "workload", `echo $$`)
	iorBin := writeScript(t, tmpDir, "ior",
		`touch test.ior.zst test.svg`)

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

	if len(entries) == 0 {
		t.Fatal("expected files in output dir, got none")
	}

	for _, e := range entries {
		name := e.Name()
		validSuffix := strings.HasSuffix(name, ".ior.zst") ||
			strings.HasSuffix(name, ".svg")
		if !validSuffix {
			t.Errorf("unexpected file in output dir: %s", name)
		}
	}
}

func TestCleanupDetectsLeakedWorkloadTempDir(t *testing.T) {
	before := listWorkloadTempDirs(t)

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
		t.Error("leak detection failed: new ioworkload temp dir was not detected")
	}
}

func TestCleanupLeakedWorkloadTempDirCaughtByAssertion(t *testing.T) {
	before := listWorkloadTempDirs(t)
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	// Fake workload that creates a temp dir but does NOT clean it up.
	// This simulates a killed workload whose defer cleanup() never ran.
	workloadBin := writeScript(t, tmpDir, "workload",
		`echo $$; mktemp -d /tmp/ioworkload-leaked-test-XXXXXX >/dev/null`)
	iorBin := writeScript(t, tmpDir, "ior", `exit 0`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	h.Run("test", 5) //nolint:errcheck

	// Verify that a leaked dir IS detected.
	after := listWorkloadTempDirs(t)
	var leaked []string
	for dir := range after {
		if _, existed := before[dir]; !existed {
			leaked = append(leaked, dir)
		}
	}
	if len(leaked) == 0 {
		t.Error("expected to detect leaked ioworkload temp dir, found none")
	}
	// Clean up the intentionally leaked dir.
	for _, dir := range leaked {
		os.RemoveAll(dir)
	}
}

func TestCleanupOutputDirEmptyAfterIorFailure(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	workloadBin := writeScript(t, tmpDir, "workload", `echo $$`)
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

	if len(entries) != 0 {
		t.Fatalf("expected empty output dir after ior failure, found %d entries", len(entries))
	}
}

func TestCleanupNoArtifactsOutsideOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	workloadBin := writeScript(t, tmpDir, "workload", `echo $$`)
	iorBin := writeScript(t, tmpDir, "ior", `touch test.ior.zst`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	h.Run("test", 5) //nolint:errcheck

	// Verify no artifacts were created in the script dir (outside outputDir).
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read tmp dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ior.zst") ||
			strings.HasSuffix(e.Name(), ".svg") {
			t.Errorf("artifact leaked to script dir: %s", e.Name())
		}
	}
}
