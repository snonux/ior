package integrationtests

import "testing"

func TestProcessExecLifecycle(t *testing.T) {
	result, _ := runScenarioResult(t, "process-exec-lifecycle", []ExpectedEvent{
		{
			Tracepoint:   "enter_execve",
			PathContains: "ior-missing-execve-only",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint:   "enter_execveat",
			PathContains: "ior-missing-execveat-only",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})

	assertEventDurationPositive(t, result, ExpectedEvent{
		Tracepoint:   "enter_execve",
		PathContains: "ior-missing-execve-only",
		Comm:         "ioworkload",
	})
	assertEventDurationPositive(t, result, ExpectedEvent{
		Tracepoint:   "enter_execveat",
		PathContains: "ior-missing-execveat-only",
		Comm:         "ioworkload",
	})
}
