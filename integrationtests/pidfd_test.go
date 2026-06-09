package integrationtests

import "testing"

var pidfdTraceArgs = []string{"-trace-syscalls", "pidfd_open,pidfd_getfd,pidfd_send_signal,openat,write,close"}

// TestPidfdGetfdSuccess asserts the resolved path of the pidfd_getfd event is
// the duplicated source file, NOT the pidfd's anon_inode.
//
// The BPF enter handler captures args[0] = the pidfd (correct: the pidfd is the
// operand being acted on). One might therefore expect the resolved path to be
// the self-pidfd's "anon_inode:[pidfd]". It is not, and the PathContains below
// is deterministic and meaningful for a concrete reason: pidfd_getfd is an
// fd-transfer op. At exit, applyFdTransferOp (internal/eventloop_exit.go) drops
// the pidfd and re-points the event's file to the RETURNED fd (the duplicate of
// the source fd). For a self-pidfd that returned fd lives in this same process
// and refers to the very same open file, so /proc/<pid>/fd/<newfd> readlinks to
// "pidfd-getfd-source.txt". Verified deterministic across repeated runs.
func TestPidfdGetfdSuccess(t *testing.T) {
	runScenarioResultWithIorArgs(t, "pidfd-getfd-success", []ExpectedEvent{
		{
			PathContains: "pidfd-getfd-source.txt",
			Tracepoint:   "enter_pidfd_getfd",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, pidfdTraceArgs)
}

func TestPidfdGetfdFailure(t *testing.T) {
	runScenarioResultWithIorArgs(t, "pidfd-getfd-failure", []ExpectedEvent{
		{
			Tracepoint: "enter_pidfd_getfd",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, pidfdTraceArgs)
}

// TestPidfdSendSignal asserts ior captures the enter_pidfd_send_signal
// tracepoint when ioworkload issues a pidfd_send_signal liveness probe (sig 0)
// against its own pidfd. The BPF enter handler captures args[0] = the pidfd
// (FamilyIPC, KindFd); the exit is UNCLASSIFIED. Signal 0 delivers nothing, so
// the probe is safe to target self.
func TestPidfdSendSignal(t *testing.T) {
	runScenarioResultWithIorArgs(t, "pidfd-send-signal", []ExpectedEvent{
		{
			Tracepoint: "enter_pidfd_send_signal",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, pidfdTraceArgs)
}
