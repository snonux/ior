package integrationtests

import "testing"

func TestAttachTracepointsIncludeFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)

	// Only load openat tracepoints so write events from the workload are not captured.
	result, pid, err := h.RunWithIorArgs("open-rdonly-write", defaultDuration, []string{
		"-tps", "^sys_enter_openat$,^sys_exit_openat$",
	})
	if err != nil {
		t.Fatalf("run scenario open-rdonly-write with include filter: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			PathContains: "rdonlyfile.txt",
			Tracepoint:   "enter_openat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	AssertEventsAbsent(t, result, []ExpectedEvent{
		{
			PathContains: "rdonlyfile.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
		},
	})
}

func TestAttachTracepointsExcludeByInclusion(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)

	// Negative case: include only write tracepoints; openat must not be captured.
	result, pid, err := h.RunWithIorArgs("open-rdonly-write", defaultDuration, []string{
		"-tps", "^sys_enter_write$,^sys_exit_write$",
	})
	if err != nil {
		t.Fatalf("run scenario open-rdonly-write with write-only include filter: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			Tracepoint: "enter_write",
			MinCount:   1,
		},
	})
	AssertEventsAbsent(t, result, []ExpectedEvent{
		{
			Tracepoint: "enter_openat",
		},
	})
}
