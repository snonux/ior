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

// TestOpenOpenat2 exercises the raw openat2(2) syscall. openat2 differs from
// open/openat in that its flags/mode live inside an open_how struct (args[2]),
// not a plain int; the path is still at args[1]. This test verifies ior reads
// the path from args[1] (not the dirfd at args[0] nor the struct ptr at args[2])
// and that the enter_openat2 tracepoint is captured end-to-end.
func TestOpenOpenat2(t *testing.T) {
	runScenario(t, "open-openat2", []ExpectedEvent{
		{
			PathContains: "openat2file.txt",
			Tracepoint:   "enter_openat2",
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

	var (
		found  bool
		maxGap uint64
	)
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), "enter_openat") {
			continue
		}
		if !strings.Contains(rec.Path, "gap-shared.txt") {
			continue
		}
		found = true
		if rec.Cnt.DurationToPrev > maxGap {
			maxGap = rec.Cnt.DurationToPrev
		}
	}

	if !found {
		t.Fatalf("did not find openat record for gap-shared.txt")
	}
	if maxGap < minGapNs {
		t.Fatalf("max durationToPrev for openat gap-shared.txt = %d ns, want >= %d ns", maxGap, minGapNs)
	}
}
