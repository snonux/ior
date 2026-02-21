package integrationtests

import (
	"strings"
	"testing"
)

func TestWorkloadCrashReportsError(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.Run("crash", 5)
	if err == nil {
		t.Fatal("expected error from crashed workload, got nil")
	}
	if pid == 0 {
		t.Fatal("expected non-zero PID from started workload")
	}
	if !strings.Contains(err.Error(), "workload") {
		t.Errorf("error should mention workload, got: %v", err)
	}
	if len(result.Records) != 0 {
		t.Errorf("expected no records from crashed workload, got %d", len(result.Records))
	}
}
