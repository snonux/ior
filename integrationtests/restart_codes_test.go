package integrationtests

import (
	"slices"
	"testing"

	iorparquet "ior/internal/parquet"
)

// restartTraceArgs traces exactly the calls the signal-restart workload makes.
// restart_syscall is included so a regression that reports the kernel restart
// path as errors would show up alongside it.
var restartTraceArgs = []string{
	"-trace-syscalls", "read,write,pipe2,clock_nanosleep,restart_syscall",
}

// TestKernelRestartCodesAreNotErrors covers task aq2. A signal that interrupts
// a blocked syscall makes it exit with a kernel-internal restart code
// (-ERESTARTSYS -512, -ERESTART_RESTARTBLOCK -516) that user space never sees.
// ior keeps the raw return value visible but must not flag such rows as
// errors.
//
// The workload interrupts a blocking read and a nanosleep with SIGUSR1, which
// the Go runtime handles with SA_RESTART. The sleep's -516 becomes EINTR for
// the program (a handler ran, so no restart_syscall follows) and its held row
// is released unchanged. The read's -512 is restarted by the kernel after the
// handler, and since task 103 that re-execution is folded: the read is ONE
// row with the final return value, and no -512 read row is left. (A -512 row
// that must stay - the program really got EINTR - is covered by
// TestSignalRestartedReadIsOneRow.)
func TestKernelRestartCodesAreNotErrors(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "signal-restart", defaultDuration,
		restartTraceArgs, []string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})

	notError := false
	AssertRowsPresent(t, rows, []ExpectedRow{
		{Syscall: "read", Comm: "ioworkload", RetVal: ptrTo(int64(1)), IsError: &notError},
		{Syscall: "clock_nanosleep", Comm: "ioworkload", RetVal: ptrTo(int64(-516)), IsError: &notError},
	})

	for _, row := range rows {
		restart := row.Ret == -512 || row.Ret == -513 || row.Ret == -514 || row.Ret == -516
		if restart && row.IsError {
			t.Errorf("%s ret=%d is flagged is_error=true; kernel restart codes are not errors",
				row.Syscall, row.Ret)
		}
		if row.Syscall == "read" && row.Ret == -512 {
			t.Errorf("read ret=-512 was not folded into its re-execution: %+v", row)
		}
	}
}

// reexecReadFd mirrors cmd/ioworkload's reexecReadFd: the descriptor the
// signal-reexec scenario's blocking reads use.
const reexecReadFd = int32(200)

// reexecRows runs the signal-reexec workload and returns the rows of its
// reading (main) thread that the tests judge, in emission order: the reads on
// the scenario's descriptor and, when traced, the rt_sigreturn calls.
func reexecRows(t *testing.T, syscalls string) []iorparquet.Record {
	t.Helper()
	rows, pid := runParquetScenarioRows(t, "signal-reexec", defaultDuration,
		[]string{"-trace-syscalls", syscalls}, []string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})
	var judged []iorparquet.Record
	for _, row := range rows {
		// main.go pins the scenario to the main thread, so its tid is the pid.
		if row.TID != uint32(pid) {
			continue
		}
		if (row.Syscall == "read" && row.FD == reexecReadFd) || row.Syscall == "rt_sigreturn" {
			judged = append(judged, row)
		}
	}
	return judged
}

// requireReexecReads checks the scenario's reads among judged: exactly four
// rows returning 1, 2, -512 and 3, in that order and none flagged an error,
// and returns their indexes in judged.
func requireReexecReads(t *testing.T, judged []iorparquet.Record) []int {
	t.Helper()
	var reads []int
	var rets []int64
	for i, row := range judged {
		if row.Syscall != "read" {
			continue
		}
		reads = append(reads, i)
		rets = append(rets, row.Ret)
		if row.IsError {
			t.Errorf("read ret=%d is flagged is_error=true: %+v", row.Ret, row)
		}
	}
	want := []int64{1, 2, -512, 3}
	if !slices.Equal(rets, want) {
		t.Fatalf("the reading thread's reads returned %v, want %v: a kernel-restarted read is one row, "+
			"the program's own retry after EINTR is a second one. Rows: %+v", rets, want, judged)
	}
	return reads
}

// TestSignalRestartedReadIsOneRow covers task 103 end to end. The signal-reexec
// workload has a blocking read interrupted three times, and checks itself
// what the program observed each time:
//
//   - by SIGSTOP/SIGCONT (no handler): the kernel re-executes the read, the
//     program sees one read returning 1 byte. ONE row, ret 1.
//   - by a handler installed with SA_RESTART: the handler runs, the kernel
//     re-executes the read, the program sees one read returning 2 bytes. ONE
//     row, ret 2.
//   - by a handler without SA_RESTART: the program gets EINTR and calls read
//     again itself. TWO rows, ret -512 (not an error) and ret 3 - the
//     negative control: a retry the program made must never be folded.
//
// Before the fold the first two were two rows each (ret -512, then the
// result). rt_sigreturn is deliberately not traced here: the proof comes from
// the restart-fold probes, not from the handler's syscalls being visible.
func TestSignalRestartedReadIsOneRow(t *testing.T) {
	judged := reexecRows(t, "read,write,pipe2,dup3")
	reads := requireReexecReads(t, judged)
	for _, i := range reads[:2] {
		row := judged[i]
		if row.Bytes != uint64(row.Ret) {
			t.Errorf("folded read ret=%d has bytes=%d, want the bytes of the final return", row.Ret, row.Bytes)
		}
		if row.LatencyNS == 0 {
			t.Errorf("folded read ret=%d has no latency: %+v", row.Ret, row)
		}
	}
}

// TestSignalRestartedReadFoldsAroundTheHandlersRows is the same run with
// rt_sigreturn traced, so the signal handlers' own syscalls are rows on the
// reading thread. They must neither prevent the fold after the SA_RESTART
// handler nor be swallowed by it: a handler return is reported between the
// stopped read and the SA_RESTART read's row (it completes before the call it
// interrupted), and another between the EINTR row and the program's retry.
func TestSignalRestartedReadFoldsAroundTheHandlersRows(t *testing.T) {
	judged := reexecRows(t, "read,write,pipe2,dup3,rt_sigreturn")
	reads := requireReexecReads(t, judged)
	if reads[1]-reads[0] < 2 {
		t.Errorf("no rt_sigreturn row between the stopped read and the SA_RESTART read: %+v", judged)
	}
	if reads[3]-reads[2] < 2 {
		t.Errorf("no rt_sigreturn row between the EINTR read and the program's retry: %+v", judged)
	}
}

// reexecManyReads and reexecManyFdBase mirror cmd/ioworkload's
// reexecSampledReads and reexecSampledFdBase: the signal-reexec-many scenario
// makes that many stopped reads, read i through descriptor reexecManyFdBase+i
// and returning i+1 bytes.
const (
	reexecManyReads  = 32
	reexecManyFdBase = int32(300)
)

// reexecManyRows runs the signal-reexec-many workload with read traced (plus
// extraArgs) and returns the reading thread's rows on the scenario's
// descriptors, grouped by read index, in emission order.
func reexecManyRows(t *testing.T, extraArgs ...string) [][]iorparquet.Record {
	t.Helper()
	rows, pid := runParquetScenarioRows(t, "signal-reexec-many", defaultDuration,
		append([]string{"-trace-syscalls", "read"}, extraArgs...), []string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})
	byRead := make([][]iorparquet.Record, reexecManyReads)
	for _, row := range rows {
		// main.go pins the scenario to the main thread, so its tid is the pid.
		i := int(row.FD - reexecManyFdBase)
		if row.TID != uint32(pid) || row.Syscall != "read" || i < 0 || i >= reexecManyReads {
			continue
		}
		byRead[i] = append(byRead[i], row)
	}
	return byRead
}

// TestSignalStoppedReadsEachFoldIntoOneRow is the fold in bulk: 32 blocking
// reads, each stopped and continued once while blocked. Every one must be
// exactly one row, on its own descriptor and with its own byte count - the
// descriptor comes from the call's first enter and the count from the
// re-execution's exit, so a row with both right is that call and no other.
func TestSignalStoppedReadsEachFoldIntoOneRow(t *testing.T) {
	for i, rows := range reexecManyRows(t) {
		want := int64(i + 1)
		if len(rows) != 1 || rows[0].Ret != want || rows[0].Bytes != uint64(want) || rows[0].IsError {
			t.Errorf("read %d (fd %d): rows %+v, want exactly one row returning %d bytes",
				i, reexecManyFdBase+int32(i), rows, want)
		}
	}
}

// TestSignalStoppedReadsUnderSamplingNeverSpanTwoCalls is the same workload
// with read sampled 1-in-2. The kernel's announcement of a re-execution goes
// out before the sampling decision, so half the announced calls are never
// recorded; the interrupted row must then stay as it is rather than take the
// thread's next read - a different call - for its continuation (before the
// announcement was tied to its enter's timestamp, such rows spanned two to
// four reads: descriptor of one, byte count and end time of a later one).
//
// The check is by value, not by timing. Whatever the sampler picks, a row on
// descriptor i can only be read i: it returns i+1 bytes (the call, folded or
// its re-execution alone) or -512 (the interrupted half alone), each at most
// once. Which rows exist at all is the sampler's choice, so only their
// presence in general is required.
func TestSignalStoppedReadsUnderSamplingNeverSpanTwoCalls(t *testing.T) {
	total := 0
	for i, rows := range reexecManyRows(t, "-syscall-sampling-syscalls", "read=2") {
		want := int64(i + 1)
		finals, interrupted := 0, 0
		for _, row := range rows {
			total++
			switch row.Ret {
			case want:
				finals++
			case -512:
				interrupted++
			default:
				t.Errorf("read %d (fd %d) has a row returning %d: only %d or -512 belong to this call, "+
					"another call was folded into it: %+v", i, reexecManyFdBase+int32(i), row.Ret, want, row)
			}
			if row.IsError {
				t.Errorf("read %d: row flagged is_error=true: %+v", i, row)
			}
		}
		if finals > 1 || interrupted > 1 {
			t.Errorf("read %d (fd %d): %d rows returning %d and %d returning -512, want at most one each: %+v",
				i, reexecManyFdBase+int32(i), finals, want, interrupted, rows)
		}
	}
	// 64 sampled invocations at 1-in-2: no row at all means the trace or the
	// workload did not run as intended.
	if total == 0 {
		t.Fatal("no row of the scenario's reads was recorded")
	}
}

// stopRestartSleepNs mirrors cmd/ioworkload's stopRestartSleepNs.
const stopRestartSleepNs = int64(600_000_000)

// TestStoppedSleepIsOneRow covers task fs2. The stop-restart workload sleeps
// 600ms in clock_nanosleep while an external stopper sends SIGSTOP and, 200ms
// later, SIGCONT. The kernel ends the call with -516 and resumes it through
// restart_syscall; before the fold ior reported two rows for the one call
// (clock_nanosleep ret=-516, then restart_syscall ret=0 without the requested
// sleep). Now the sleeping thread must show exactly one clock_nanosleep row:
// ret 0, the requested 600ms, and a latency covering the whole call. Other
// Go runtime threads also get stopped inside timed futex waits, whose
// restart_syscall continuations stay rows of their own because futex is not
// traced here, so only the sleeping (main) thread is checked for leftovers.
func TestStoppedSleepIsOneRow(t *testing.T) {
	rows, pid := runParquetScenarioRows(t, "stop-restart", defaultDuration,
		[]string{"-trace-syscalls", "clock_nanosleep,restart_syscall"},
		[]string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})

	var sleeps []iorparquet.Record
	for _, row := range rows {
		// main.go pins the scenario to the main thread, so its tid is the pid.
		if row.TID != uint32(pid) {
			continue
		}
		switch row.Syscall {
		case "restart_syscall":
			t.Errorf("restart_syscall row on the sleeping thread was not folded: %+v", row)
		case "clock_nanosleep":
			sleeps = append(sleeps, row)
		}
	}
	if len(sleeps) != 1 {
		t.Fatalf("sleeping thread has %d clock_nanosleep rows, want exactly 1: %+v", len(sleeps), sleeps)
	}
	sleep := sleeps[0]
	if sleep.Ret != 0 || sleep.IsError {
		t.Errorf("folded row ret=%d is_error=%t, want ret=0 is_error=false", sleep.Ret, sleep.IsError)
	}
	if sleep.RequestedSleepNS != stopRestartSleepNs {
		t.Errorf("folded row requested_sleep_ns=%d, want %d", sleep.RequestedSleepNS, stopRestartSleepNs)
	}
	// The resumed sleep ends at the original deadline, so the whole call
	// lasts at least the request (unless the stop outlasted it, which only
	// makes it longer).
	if sleep.LatencyNS < uint64(stopRestartSleepNs) {
		t.Errorf("folded row latency_ns=%d, want >= the requested %d", sleep.LatencyNS, stopRestartSleepNs)
	}
}

// handledSleepNs mirrors cmd/ioworkload's handledSleepNs.
const handledSleepNs = int64(3_000_000_000)

// TestSignalHandledSleepIsNotFoldedWithALaterStoppedCall covers task t13. The
// signal-handled-sleep workload has a 3s clock_nanosleep cut short by a
// handled SIGUSR1 (the program gets EINTR) and then a nanosleep(2) that is
// stopped and continued, which the kernel resumes through restart_syscall. The
// trace records clock_nanosleep and restart_syscall only, so the handler's
// rt_sigreturn and the nanosleep are silent: the sleeping thread's records are
// the clock_nanosleep with its -516 exit and then the restart_syscall of the
// OTHER call. Folding by "the thread's next record is restart_syscall" made
// one clock_nanosleep row of them, returning 0 and lasting until the later
// call ended.
//
// The thread must show the sleep as it was - ret -516, not an error, shorter
// than its request - and the later call's restart_syscall as a row of its own
// that starts after the sleep row ended. The workload checks what the program
// saw (EINTR, then 0) and sends each signal only once the thread is blocked in
// the call it is meant for, so nothing here depends on timing.
func TestSignalHandledSleepIsNotFoldedWithALaterStoppedCall(t *testing.T) {
	rows, pid := runParquetScenarioRows(t, "signal-handled-sleep", defaultDuration,
		[]string{"-trace-syscalls", "clock_nanosleep,restart_syscall"},
		[]string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})

	var sleeps, restarts []iorparquet.Record
	for _, row := range rows {
		// main.go pins the scenario to the main thread, so its tid is the pid.
		if row.TID != uint32(pid) {
			continue
		}
		switch {
		case row.Syscall == "clock_nanosleep" && row.RequestedSleepNS == handledSleepNs:
			sleeps = append(sleeps, row)
		case row.Syscall == "restart_syscall":
			restarts = append(restarts, row)
		}
	}
	if len(sleeps) != 1 || len(restarts) != 1 {
		t.Fatalf("sleeping thread has %d rows of the handled sleep and %d restart_syscall rows, want 1 and 1: %+v %+v",
			len(sleeps), len(restarts), sleeps, restarts)
	}
	sleep, restart := sleeps[0], restarts[0]
	if sleep.Ret != -516 || sleep.IsError {
		t.Errorf("handled sleep ret=%d is_error=%t, want ret=-516 is_error=false: the program got EINTR, "+
			"nothing resumed the call: %+v", sleep.Ret, sleep.IsError, sleep)
	}
	if sleep.LatencyNS >= uint64(handledSleepNs) {
		t.Errorf("handled sleep latency_ns=%d, want less than the requested %d: the signal cut it short",
			sleep.LatencyNS, handledSleepNs)
	}
	if restart.Ret != 0 || restart.IsError {
		t.Errorf("restart_syscall ret=%d is_error=%t, want the stopped nanosleep's result 0: %+v",
			restart.Ret, restart.IsError, restart)
	}
	if restart.TimeNS < sleep.TimeNS+sleep.LatencyNS {
		t.Errorf("restart_syscall starts at %d, before the sleep row ends at %d: the sleep row spans the later call",
			restart.TimeNS, sleep.TimeNS+sleep.LatencyNS)
	}
}
