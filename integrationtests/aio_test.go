package integrationtests

import "testing"

// aioTraceArgs traces the classic Linux AIO (io_setup) family syscalls plus
// close. io_setup/io_destroy are classified KindNull (FamilyAIO): the enter
// event captures no fd/path (nr_events is a count, ctx_idp an output pointer)
// and the exit event carries the raw return value.
var aioTraceArgs = []string{"-trace-syscalls", "io_setup,io_destroy,close"}

// TestAioSetup exercises io_setup(2) end-to-end and asserts ior records the
// enter_io_setup tracepoint for the AIO family workload.
func TestAioSetup(t *testing.T) {
	runScenarioResultWithIorArgs(t, "aio-setup", []ExpectedEvent{
		{
			Tracepoint: "enter_io_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, aioTraceArgs)
}

// TestAioSetupEinval drives io_setup(2) with nr_events = 0 (EINVAL). The
// syscall fails, but ior still captures the enter_io_setup tracepoint.
func TestAioSetupEinval(t *testing.T) {
	runScenarioResultWithIorArgs(t, "aio-setup-einval", []ExpectedEvent{
		{
			Tracepoint: "enter_io_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, aioTraceArgs)
}

// aioSubmitTraceArgs additionally traces io_submit so the submit scenario can
// assert on its enter tracepoint. io_submit is KindNull (FamilyAIO): the enter
// event captures no fd/path (ctx_id is an AIO context handle, not an fd, and
// iocbpp is an opaque userspace pointer) and the exit event carries the raw
// return value (a count of iocbs submitted, classified UNCLASSIFIED).
var aioSubmitTraceArgs = []string{"-trace-syscalls", "io_setup,io_submit,io_destroy,close"}

// TestAioSubmit exercises io_submit(2) end-to-end: the workload sets up an AIO
// context and submits one real iocb (a positional write). ior must record the
// enter_io_submit tracepoint for the AIO family workload.
func TestAioSubmit(t *testing.T) {
	runScenarioResultWithIorArgs(t, "aio-submit", []ExpectedEvent{
		{
			Tracepoint: "enter_io_submit",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, aioSubmitTraceArgs)
}

// aioGeteventsTraceArgs additionally traces io_getevents so the getevents
// scenario can assert on its enter tracepoint. io_getevents is KindNull
// (FamilyAIO): the enter event captures no fd/path (ctx_id is an AIO context
// handle, events/timeout are opaque userspace pointers) and the exit event
// carries the raw return value (a count of events reaped, UNCLASSIFIED).
var aioGeteventsTraceArgs = []string{"-trace-syscalls", "io_setup,io_submit,io_getevents,io_destroy,close"}

// TestAioGetevents exercises io_getevents(2) end-to-end: the workload sets up an
// AIO context, submits one real iocb (a positional write), then reaps its
// completion with io_getevents. ior must record the enter_io_getevents
// tracepoint for the AIO family workload.
func TestAioGetevents(t *testing.T) {
	runScenarioResultWithIorArgs(t, "aio-getevents", []ExpectedEvent{
		{
			Tracepoint: "enter_io_getevents",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, aioGeteventsTraceArgs)
}

// aioCancelTraceArgs additionally traces io_cancel and io_getevents so the
// cancel scenario can assert on its enter tracepoint and still drain the
// completion ring. io_cancel is KindNull (FamilyAIO): the enter event captures
// no fd/path (ctx_id is an AIO context handle, iocb/result are opaque userspace
// pointers) and the exit event carries the raw return value (UNCLASSIFIED).
var aioCancelTraceArgs = []string{"-trace-syscalls", "io_setup,io_submit,io_cancel,io_getevents,io_destroy,close"}

// TestAioCancel exercises io_cancel(2): the workload submits one real iocb and
// then attempts to cancel it. io_cancel races the I/O completion and frequently
// returns -EINVAL/-EAGAIN, so the test asserts ONLY on the enter_io_cancel
// tracepoint (which fires regardless of the return value), never on success.
func TestAioCancel(t *testing.T) {
	runScenarioResultWithIorArgs(t, "aio-cancel", []ExpectedEvent{
		{
			Tracepoint: "enter_io_cancel",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, aioCancelTraceArgs)
}
