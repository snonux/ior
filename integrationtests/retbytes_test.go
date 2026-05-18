package integrationtests

import "testing"

func TestRetbytesPhaseA(t *testing.T) {
	const payloadLen = uint64(18)

	result, _ := runScenarioResult(t, "retbytes-phase-a", []ExpectedEvent{
		{Tracepoint: "enter_sendto", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_recvfrom", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sendmsg", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_recvmsg", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sendfile64", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_splice", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_tee", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_process_vm_writev", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_process_vm_readv", Comm: "ioworkload", MinCount: 1},
	})

	for _, tracepoint := range []string{
		"enter_sendto",
		"enter_recvfrom",
		"enter_sendmsg",
		"enter_recvmsg",
		"enter_sendfile64",
		"enter_splice",
		"enter_tee",
		"enter_process_vm_writev",
		"enter_process_vm_readv",
	} {
		exp := ExpectedEvent{Tracepoint: tracepoint, Comm: "ioworkload"}
		assertEventBytesAtLeast(t, result, exp, payloadLen)
		assertEventDurationPositive(t, result, exp)
	}
}
