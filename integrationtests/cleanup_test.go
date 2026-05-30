package integrationtests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workloadTempDirPrefix is the prefix used by ioworkload's makeTempDir.
const workloadTempDirPrefix = "ioworkload-"

// uniqueLeakPrefix returns a temp-dir prefix that is unique to this single test
// invocation. It embeds the running PID and the per-test name so that the
// before/after leak-detection diff only ever observes directories created BY
// THIS test, never the ioworkload-<scenario>-* directories that real scenario
// workloads legitimately create in the shared system temp root while they run.
//
// Scoping detection (and the subsequent cleanup RemoveAll) to this unique
// prefix is what makes the leak-detection tests order- and concurrency-safe:
// the previous implementation scanned os.TempDir() for ANY "ioworkload-"
// directory, so when other (parallel) scenario tests had in-flight temp dirs,
// this test both falsely attributed them as leaks and deleted them out from
// under the still-running tests.
func uniqueLeakPrefix(t *testing.T) string {
	t.Helper()
	// Replace path separators so the prefix is a valid single dir-name
	// component (subtests embed "/" in t.Name()).
	safeName := strings.ReplaceAll(t.Name(), "/", "_")
	return fmt.Sprintf("%sleak-%d-%s-", workloadTempDirPrefix, os.Getpid(), safeName)
}

// listWorkloadTempDirsWithPrefix returns the set of directories in the system
// temp directory whose name starts with prefix. Restricting to a caller-chosen
// prefix keeps detection scoped to a single test's own directories.
func listWorkloadTempDirsWithPrefix(t *testing.T, prefix string) map[string]struct{} {
	t.Helper()
	tmpDir := os.TempDir()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}

	dirs := make(map[string]struct{})
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			dirs[filepath.Join(tmpDir, e.Name())] = struct{}{}
		}
	}
	return dirs
}

// newLeakedDirs returns the directories matching prefix that appeared in the
// system temp root since the before snapshot was taken.
func newLeakedDirs(t *testing.T, prefix string, before map[string]struct{}) []string {
	t.Helper()
	after := listWorkloadTempDirsWithPrefix(t, prefix)
	var leaked []string
	for dir := range after {
		if _, existed := before[dir]; !existed {
			leaked = append(leaked, dir)
		}
	}
	return leaked
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
	// Use a prefix unique to this test so the diff cannot observe directories
	// created by any concurrently running scenario test.
	prefix := uniqueLeakPrefix(t)
	before := listWorkloadTempDirsWithPrefix(t, prefix)

	// Create a temp dir that looks like a leaked ioworkload dir.
	leaked, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("create leaked dir: %v", err)
	}
	defer os.RemoveAll(leaked)

	if len(newLeakedDirs(t, prefix, before)) == 0 {
		t.Error("leak detection failed: new ioworkload temp dir was not detected")
	}
}

func TestCleanupLeakedWorkloadTempDirCaughtByAssertion(t *testing.T) {
	// The intentionally leaked dir is created under a prefix unique to this
	// test (PID + test name). Both the snapshot scan and the cleanup below are
	// scoped to that prefix, so this test can never observe — let alone delete
	// — temp dirs belonging to other scenario tests. The template is created in
	// os.TempDir() (the same root listWorkloadTempDirsWithPrefix scans) rather
	// than a hard-coded /tmp, so detection works regardless of $TMPDIR.
	prefix := uniqueLeakPrefix(t)
	before := listWorkloadTempDirsWithPrefix(t, prefix)
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	// Fake workload that creates a temp dir but does NOT clean it up.
	// This simulates a killed workload whose defer cleanup() never ran.
	leakTemplate := filepath.Join(os.TempDir(), prefix+"XXXXXX")
	workloadBin := writeScript(t, tmpDir, "workload",
		fmt.Sprintf("echo $$; mktemp -d %q >/dev/null", leakTemplate))
	iorBin := writeScript(t, tmpDir, "ior", `exit 0`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	h.Run("test", 5) //nolint:errcheck

	// Verify that the leaked dir IS detected.
	leaked := newLeakedDirs(t, prefix, before)
	if len(leaked) == 0 {
		t.Error("expected to detect leaked ioworkload temp dir, found none")
	}
	// Clean up the intentionally leaked dir(s) — all share this test's prefix.
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
