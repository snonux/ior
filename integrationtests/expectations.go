package integrationtests

import (
	"strings"
	"testing"

	"ior/internal/flamegraph"
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
			logRecordSummary(t, result)
			continue
		}
		if exp.MinCount > 0 && totalCount < exp.MinCount {
			t.Errorf("event matching %+v has total count %d, want >= %d",
				exp, totalCount, exp.MinCount)
		}
	}
}

func logRecordSummary(t *testing.T, result TestResult) {
	t.Helper()
	limit := 20
	if len(result.Records) < limit {
		limit = len(result.Records)
	}
	t.Logf("captured %d records; first %d:", len(result.Records), limit)
	for i := 0; i < limit; i++ {
		rec := result.Records[i]
		t.Logf("  tracepoint=%s comm=%q pid=%d path=%q count=%d", rec.TraceID.String(), rec.Comm, rec.Pid, rec.Path, rec.Cnt.Count)
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

// AssertEventsAbsent verifies that none of the specified events appear in the test result.
// Each ExpectedEvent must have at least one filter field set to avoid accidentally
// matching all records.
func AssertEventsAbsent(t *testing.T, result TestResult, absent []ExpectedEvent) {
	t.Helper()
	for _, exp := range absent {
		if exp.PathContains == "" && exp.Tracepoint == "" && exp.Comm == "" {
			t.Errorf("AssertEventsAbsent: ExpectedEvent must have at least one filter field set: %+v", exp)
			continue
		}
		for _, rec := range result.Records {
			if matchesExpectation(rec, exp) {
				t.Errorf("event should be absent but was found: %+v (path=%q tracepoint=%s comm=%q)",
					exp, rec.Path, rec.TraceID.String(), rec.Comm)
				break
			}
		}
	}
}

func matchesExpectation(rec flamegraph.IterRecord, exp ExpectedEvent) bool {
	if exp.PathContains != "" && !strings.Contains(rec.Path, exp.PathContains) {
		return false
	}
	if exp.Tracepoint != "" && !strings.Contains(rec.TraceID.String(), exp.Tracepoint) {
		return false
	}
	if exp.Comm != "" && rec.Comm != "" && rec.Comm != exp.Comm {
		return false
	}
	return true
}
