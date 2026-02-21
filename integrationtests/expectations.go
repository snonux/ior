package integrationtests

import (
	"ior/internal/flamegraph"
	"strings"
	"testing"
)

// ExpectedEvent describes an I/O event that should appear in the test output.
type ExpectedEvent struct {
	PathContains string // substring match on file path
	Tracepoint   string // tracepoint name substring, e.g. "openat"
	Comm         string // expected comm name, e.g. "ioworkload"
	MinCount     uint64 // minimum total occurrences across all matching records
}

// AssertEventsPresent verifies that each expected event is found in the test result.
// Counts are summed across all matching records before comparing to MinCount.
func AssertEventsPresent(t *testing.T, result TestResult, expected []ExpectedEvent) {
	t.Helper()
	for _, exp := range expected {
		var totalCount uint64
		var matched bool
		for _, rec := range result.Records {
			if matchesExpectation(rec, exp) {
				matched = true
				totalCount += rec.Cnt.Count
			}
		}
		if !matched {
			t.Errorf("expected event not found: %+v", exp)
			continue
		}
		if exp.MinCount > 0 && totalCount < exp.MinCount {
			t.Errorf("event matching %+v has total count %d, want >= %d",
				exp, totalCount, exp.MinCount)
		}
	}
}

// AssertNoUnexpectedComm verifies all records have the expected comm name.
// Records with empty comm are skipped because BPF may capture events before
// the process name is set in the task struct.
func AssertNoUnexpectedComm(t *testing.T, result TestResult, expectedComm string) {
	t.Helper()
	var count int
	for _, rec := range result.Records {
		if rec.Comm == "" {
			continue
		}
		if rec.Comm != expectedComm {
			count++
			if count <= 5 {
				t.Logf("unexpected comm %q (pid=%d tracepoint=%s path=%q)",
					rec.Comm, rec.Pid, rec.TraceID.String(), rec.Path)
			}
		}
	}
	if count > 0 {
		t.Fatalf("found %d records with unexpected comm (want %q)", count, expectedComm)
	}
}

// AssertNoUnexpectedPID verifies all records belong to the expected PID.
// Accepts int to match os.Getpid() return type.
func AssertNoUnexpectedPID(t *testing.T, result TestResult, expectedPID int) {
	t.Helper()
	pid := uint32(expectedPID)
	var count int
	for _, rec := range result.Records {
		if rec.Pid != pid {
			count++
			if count <= 5 {
				t.Logf("unexpected PID %d (tracepoint=%s path=%q comm=%q)",
					rec.Pid, rec.TraceID.String(), rec.Path, rec.Comm)
			}
		}
	}
	if count > 0 {
		t.Fatalf("found %d records with unexpected PID (want %d)", count, expectedPID)
	}
}

func matchesExpectation(rec flamegraph.IterRecord, exp ExpectedEvent) bool {
	if exp.PathContains != "" && !strings.Contains(rec.Path, exp.PathContains) {
		return false
	}
	if exp.Tracepoint != "" && !strings.Contains(rec.TraceID.String(), exp.Tracepoint) {
		return false
	}
	if exp.Comm != "" && rec.Comm != exp.Comm {
		return false
	}
	return true
}
