package integrationtests

import (
	"strings"
	"testing"
)

func TestOpenBasic(t *testing.T) {
	runScenario(t, "open-basic", []ExpectedEvent{
		{
			PathContains: "testfile.txt",
			Tracepoint:   "enter_openat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestOpenCreat(t *testing.T) {
	runScenario(t, "open-creat", []ExpectedEvent{
		{
			PathContains: "creatfile.txt",
			Tracepoint:   "enter_creat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestOpenByHandleAt(t *testing.T) {
	runScenario(t, "open-by-handle-at", []ExpectedEvent{
		{
			PathContains: "handlefile.txt",
			Tracepoint:   "enter_open_by_handle_at",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestOpenEnoent(t *testing.T) {
	runScenario(t, "open-enoent", []ExpectedEvent{
		{
			PathContains: "enoentfile.txt",
			Tracepoint:   "enter_openat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestOpenRdonlyWrite(t *testing.T) {
	runScenario(t, "open-rdonly-write", []ExpectedEvent{
		{
			PathContains: "rdonlyfile.txt",
			Tracepoint:   "enter_openat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "rdonlyfile.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestOpenPidFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.Run("open-pid-filter", defaultDuration)
	if err != nil {
		t.Fatalf("run scenario open-pid-filter: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")

	// Parent's file should be captured.
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			PathContains: "parentfile.txt",
			Tracepoint:   "enter_openat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})

	// Child's file should NOT be captured (different PID).
	// Scope to openat so parent cleanup unlink/rmdir operations on childfile
	// do not create false positives.
	AssertEventsAbsent(t, result, []ExpectedEvent{
		{
			PathContains: "childfile.txt",
			Tracepoint:   "enter_openat",
		},
	})
}

func TestOpenDurationGap(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.Run("open-duration-gap", defaultDuration)
	if err != nil {
		t.Fatalf("run scenario open-duration-gap: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")

	// We intentionally sleep 800ms between first and second openat.
	const minGapNs = uint64(500 * 1_000_000)

	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), "enter_openat") {
			continue
		}
		if !strings.Contains(rec.Path, "gap-shared.txt") {
			continue
		}
		if rec.Cnt.DurationToPrev < minGapNs {
			t.Fatalf("durationToPrev for second openat = %d ns, want >= %d ns", rec.Cnt.DurationToPrev, minGapNs)
		}
		return
	}

	t.Fatalf("did not find openat record for gap-shared.txt")
}
