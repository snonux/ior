package integrationtests

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	iorBinaryDefault      = "../ior"
	workloadBinaryDefault = "../ioworkload"
	bpfObjectDefault      = "../ior.bpf.o"
	defaultDuration       = 10
	parallelEnvVar        = "IOR_INTEGRATION_PARALLEL"
)

func newTestHarness(t *testing.T) TestHarness {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF")
	}

	return TestHarness{
		IorBinary:      absPath(t, iorBinaryDefault),
		WorkloadBinary: absPath(t, workloadBinaryDefault),
		BpfObject:      absPath(t, bpfObjectDefault),
		OutputDir:      t.TempDir(),
	}
}

func absPath(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("resolve path %s: %v", rel, err)
	}
	return p
}

// writeScript creates an executable shell script in dir and returns its path.
func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+content+"\n"), 0o755); err != nil {
		t.Fatalf("write script %s: %v", name, err)
	}
	return path
}

func runScenario(t *testing.T, scenario string, expected []ExpectedEvent) {
	t.Helper()
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.Run(scenario, defaultDuration)
	if err != nil {
		t.Fatalf("run scenario %s: %v", scenario, err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, expected)
}

func enableParallelIfRequested(t *testing.T) {
	t.Helper()
	if os.Getenv(parallelEnvVar) == "1" {
		t.Parallel()
	}
}
