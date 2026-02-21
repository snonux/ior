package integrationtests

import "testing"

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
	AssertEventsAbsent(t, result, []ExpectedEvent{
		{
			PathContains: "childfile.txt",
		},
	})
}
