package integrationtests

import "testing"

var retbytesTraceArgs = []string{"-trace-syscalls", "sendto,recvfrom,sendmsg,recvmsg,sendmmsg,recvmmsg,sendfile64,splice,tee,process_vm_writev,process_vm_readv,socketpair,pipe2,openat,write,read,close,lseek,fcntl,unlinkat,mkdirat,getdents64"}

func TestRetbytesPhaseA(t *testing.T) {
	const payloadLen = uint64(18)

	result, _ := runScenarioResultWithIorArgs(t, "retbytes-phase-a", []ExpectedEvent{
		{Tracepoint: "enter_sendto", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_recvfrom", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sendmsg", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_recvmsg", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sendmmsg", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_recvmmsg", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sendfile64", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_splice", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_tee", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_process_vm_writev", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_process_vm_readv", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_getdents64", Comm: "ioworkload", MinCount: 1},
	}, retbytesTraceArgs)

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

	for _, tracepoint := range []string{"enter_sendmmsg", "enter_recvmmsg"} {
		exp := ExpectedEvent{Tracepoint: tracepoint, Comm: "ioworkload"}
		assertEventBytesEqual(t, result, exp, 0)
		assertEventDurationPositive(t, result, exp)
	}

	// getdents64 is READ_CLASSIFIED: a successful call on a non-empty directory
	// fills the dirent buffer and reports ctx->ret > 0. Dirent size varies with
	// filename length and alignment, so assert a conservative bytes>=1 minimum
	// rather than an exact payload length.
	getdentsExp := ExpectedEvent{Tracepoint: "enter_getdents64", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, getdentsExp, 1)
	assertEventDurationPositive(t, result, getdentsExp)
}
