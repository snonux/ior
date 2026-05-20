package integrationtests

import "testing"

func TestSecurityKeysPtracePerf(t *testing.T) {
	runScenario(t, "security-keys-ptrace-perf", []ExpectedEvent{
		{Tracepoint: "enter_keyctl", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_add_key", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_request_key", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_ptrace", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_perf_event_open", Comm: "ioworkload", MinCount: 1},
	})
}
