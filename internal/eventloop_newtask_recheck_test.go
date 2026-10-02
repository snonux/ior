package internal

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// Task xr2: a task_newtask seed used to queue one corrective /proc/<tid>/comm
// read for every new thread, which under thread churn was nearly all of the
// resolver's work and nearly always failed with ENOENT. With the task_rename
// probe attached and ring-buffer drops monitored the read is skipped
// (provisionalSeedNeedsRecheck); these tests pin both sides of that decision
// and that every lr2/fr2 path that still needs a read keeps it. The inputs of
// the trust are pinned in eventloop_newtask_trust_test.go.

const procfsComm = "procfs-name"

// countingProcfs is a resolveFn stand-in that answers name for newTaskTid and
// counts the reads of that tid.
type countingProcfs struct {
	name  string
	reads atomic.Int32
}

func (c *countingProcfs) resolve(
	_ context.Context, tid uint32,
) (string, error) {
	if tid != newTaskTid {
		return "", nil
	}
	c.reads.Add(1)
	return c.name, nil
}

// newRecheckEventLoop builds a loop over a counting resolver, with rename
// records trusted or not (set directly: trustRenameRecords has its own test).
func newRecheckEventLoop(t *testing.T, trusted bool, procfsAnswer string) (*eventLoop, *countingProcfs) {
	t.Helper()
	procfs := &countingProcfs{name: procfsAnswer}
	resolver := newCommResolver(nil)
	resolver.resolveFn = procfs.resolve
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(resolver.shutdown)
	el.renameRecordsTrusted = trusted
	return el, procfs
}

// seedNewTask delivers a task_newtask record for newTaskTid recorded at
// seedTime with comm as the inherited name.
func seedNewTask(t *testing.T, el *eventLoop, seedTime uint64, comm string) {
	t.Helper()
	ev := types.TaskNewtaskEvent{EventType: types.TASK_NEWTASK_EVENT, Time: seedTime,
		Pid: newTaskPid, Tid: newTaskTid, CloneFlags: cloneThread, CreatorPid: newTaskPid}
	copy(ev.Comm[:], comm)
	el.processRawEvent(mustBenchBytes(t, &ev), make(chan *event.Pair, 1))
}

// useNewTask feeds one syscall pair of newTaskTid (which looks the comm up),
// lets any read it queued land, and returns the comm the tid is cached with.
func useNewTask(t *testing.T, el *eventLoop) string {
	t.Helper()
	if ep := feedNewTaskSyscall(t, el); ep != nil {
		ep.Recycle()
	}
	waitForCommLookupsToDrain(t, el)
	comm, _, _ := el.commResolver.lookupCached(newTaskTid)
	return comm
}

// requireReads fails unless procfs saw exactly want reads of newTaskTid.
func requireReads(t *testing.T, procfs *countingProcfs, want int32) {
	t.Helper()
	if got := procfs.reads.Load(); got != want {
		t.Fatalf("procfs reads of tid %d = %d, want %d", newTaskTid, got, want)
	}
}

// TestTrustedRenameRecordsSkipTheNewtaskRecheck is the fix itself: with rename
// records trusted, a new thread costs no procfs read and keeps the inherited
// name, here across two syscalls.
func TestTrustedRenameRecordsSkipTheNewtaskRecheck(t *testing.T) {
	el, procfs := newRecheckEventLoop(t, true, procfsComm)
	seedNewTask(t, el, newTaskStart, inheritedComm)
	for range 2 {
		if got := useNewTask(t, el); got != inheritedComm {
			t.Fatalf("comm = %q, want the inherited %q", got, inheritedComm)
		}
	}
	requireReads(t, procfs, 0)
}

// TestUntrustedNewtaskSeedKeepsItsRecheck: without the rename probe (or
// without drop monitoring) a rename could go unreported, so the seed keeps the
// one corrective read, and only one.
func TestUntrustedNewtaskSeedKeepsItsRecheck(t *testing.T) {
	el, procfs := newRecheckEventLoop(t, false, procfsComm)
	seedNewTask(t, el, newTaskStart, inheritedComm)
	if got := useNewTask(t, el); got != procfsComm {
		t.Fatalf("comm = %q, want the procfs read's %q", got, procfsComm)
	}
	useNewTask(t, el)
	requireReads(t, procfs, 1)
}

// TestGoneThreadCostsOneReadAtMost: the read of a thread that has already
// exited comes back empty (ENOENT). Untrusted it is paid once and the seed
// survives; it is not retried on every later use (no repeated ENOENT for one
// tid). Trusted it is not paid at all.
func TestGoneThreadCostsOneReadAtMost(t *testing.T) {
	for _, tc := range []struct {
		name      string
		trusted   bool
		wantReads int32
	}{
		{"untrusted", false, 1},
		{"trusted", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el, procfs := newRecheckEventLoop(t, tc.trusted, "")
			seedNewTask(t, el, newTaskStart, inheritedComm)
			for range 3 {
				if got := useNewTask(t, el); got != inheritedComm {
					t.Fatalf("comm = %q, want the inherited %q kept", got, inheritedComm)
				}
			}
			requireReads(t, procfs, tc.wantReads)
		})
	}
}

// TestNewtaskSeedWithoutCommFallsBackToTheLookup: an empty payload seeds
// nothing, so the tid is unknown and its first use reads procfs even when
// rename records are trusted - the record named nothing to trust.
func TestNewtaskSeedWithoutCommFallsBackToTheLookup(t *testing.T) {
	el, procfs := newRecheckEventLoop(t, true, procfsComm)
	seedNewTask(t, el, newTaskStart, "")
	if got := useNewTask(t, el); got != procfsComm {
		t.Fatalf("comm = %q, want the procfs read's %q", got, procfsComm)
	}
	requireReads(t, procfs, 1)
}

// TestNewtaskSeedOlderThanADropPollKeepsItsRecheck: a seed whose record was
// reserved no later than the poll that reported drops may be followed by a
// lost rename record that the sweep (already applied) could not reach, so it
// keeps its read even when trusted. A seed recorded after that poll does not.
func TestNewtaskSeedOlderThanADropPollKeepsItsRecheck(t *testing.T) {
	const seedTime = newTaskStart
	for _, tc := range []struct {
		name       string
		lastDropNs uint64
		wantReads  int32
	}{
		{"drop poll after the seed", seedTime + 1, 1},
		{"drop poll at the seed's time", seedTime, 1},
		{"drop poll before the seed", seedTime - 1, 0},
		{"no drops seen", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el, procfs := newRecheckEventLoop(t, true, procfsComm)
			el.lastDropSeenBootNs.Store(tc.lastDropNs)
			seedNewTask(t, el, seedTime, inheritedComm)
			useNewTask(t, el)
			requireReads(t, procfs, tc.wantReads)
		})
	}
}

// TestTrustedSeedIsHealedByTheDropSweep: the trust rests on the drop monitor.
// A rename record lost after the seed shows up as a drop, and the sweep it
// triggers flags the seed for the one read the newtask path skipped.
func TestTrustedSeedIsHealedByTheDropSweep(t *testing.T) {
	el, procfs := newRecheckEventLoop(t, true, procfsComm)
	seedNewTask(t, el, newTaskStart, inheritedComm)
	useNewTask(t, el)
	requireReads(t, procfs, 0)

	el.commRefreshPending.Store(true) // the drop monitor saw lost records
	useNewTask(t, el)                 // applies the sweep, queues the read
	if got := useNewTask(t, el); got != procfsComm {
		t.Fatalf("comm after the sweep = %q, want the procfs read's %q", got, procfsComm)
	}
	requireReads(t, procfs, 1)
}

// TestTrustedSeedTakesTheRenameRecord: what makes the read unnecessary - the
// task_rename record names the renamed thread, still without a read.
func TestTrustedSeedTakesTheRenameRecord(t *testing.T) {
	el, procfs := newRecheckEventLoop(t, true, procfsComm)
	seedNewTask(t, el, newTaskStart, inheritedComm)
	el.processRawEvent(makeTaskRenameEvent(t, newTaskPid, newTaskTid, renamedComm), make(chan *event.Pair, 1))
	if got := useNewTask(t, el); got != renamedComm {
		t.Fatalf("comm = %q, want the renamed %q", got, renamedComm)
	}
	requireReads(t, procfs, 0)
}

// TestTrustedSeedKeepsTheEnterPayloadRechecks: the lr2 rechecks of an enter
// payload are independent of the newtask trust. A payload contradicting the
// seed (it may predate a sibling's rename) and an exec enter (it names the
// program about to be replaced) each still cost one read; a matching open
// payload costs none.
func TestTrustedSeedKeepsTheEnterPayloadRechecks(t *testing.T) {
	for _, tc := range []struct {
		name      string
		enter     func(t *testing.T) []byte
		exitID    types.TraceId
		wantReads int32
	}{
		{"matching open payload", func(t *testing.T) []byte { return newTaskOpenEnter(t, inheritedComm) }, types.SYS_EXIT_OPENAT, 0},
		{"contradicting open payload", func(t *testing.T) []byte { return newTaskOpenEnter(t, "contradicts") }, types.SYS_EXIT_OPENAT, 1},
		{"exec enter", newTaskExecEnter, types.SYS_EXIT_EXECVE, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el, procfs := newRecheckEventLoop(t, true, procfsComm)
			seedNewTask(t, el, newTaskStart, inheritedComm)
			// The syscall fails (ENOENT), so the exec leaves the task under its
			// name and the open registers no descriptor.
			_, exitRaw := makeExitRetEvent(t, newTaskStart+30, newTaskPid, newTaskTid, tc.exitID, -int64(syscall.ENOENT))
			if ep := feedRawPair(t, el, tc.enter(t), exitRaw); ep != nil {
				ep.Recycle()
			}
			useNewTask(t, el)
			requireReads(t, procfs, tc.wantReads)
		})
	}
}

// newTaskOpenEnter is an openat enter of newTaskTid carrying comm as payload.
func newTaskOpenEnter(t *testing.T, comm string) []byte {
	t.Helper()
	ev := types.OpenEvent{EventType: types.ENTER_OPEN_EVENT, TraceId: types.SYS_ENTER_OPENAT,
		Time: newTaskStart + 20, Pid: newTaskPid, Tid: newTaskTid, Flags: syscall.O_RDONLY,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION}
	copy(ev.Filename[:], "/etc/hosts")
	copy(ev.Comm[:], comm)
	return mustBenchBytes(t, &ev)
}

// newTaskExecEnter is an execve enter of newTaskTid under the inherited name.
func newTaskExecEnter(t *testing.T) []byte {
	t.Helper()
	ev := types.ExecEvent{EventType: types.ENTER_EXEC_EVENT, TraceId: types.SYS_ENTER_EXECVE,
		Time: newTaskStart + 20, Pid: newTaskPid, Tid: newTaskTid, Dirfd: -100,
		SchemaVersion: types.EXEC_EVENT_SCHEMA_VERSION}
	copy(ev.Filename[:], "/definitely-missing-binary")
	copy(ev.Comm[:], inheritedComm)
	return mustBenchBytes(t, &ev)
}

// TestTrustRenameRecordsNeedsTheProbeAndTheDropMonitor: the trust holds only
// when a lost rename record would be noticed, i.e. with a drop source.
func TestTrustRenameRecordsNeedsTheProbeAndTheDropMonitor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attached bool
		dropSrc  ringbufDropSource
		want     bool
	}{
		{"probe and monitor", true, &ringbufDropSourceStub{}, true},
		{"probe without monitor", true, nil, false},
		{"monitor without probe", false, &ringbufDropSourceStub{}, false},
		{"neither", false, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
			t.Cleanup(el.commResolver.shutdown)
			el.dropSrc = tc.dropSrc
			el.trustRenameRecords(tc.attached)
			if el.renameRecordsTrusted != tc.want {
				t.Fatalf("renameRecordsTrusted = %v, want %v", el.renameRecordsTrusted, tc.want)
			}
		})
	}
}

// TestDropResultStampsTheBootClock: only a poll that saw drops moves
// lastDropSeenBootNs, and it moves it to a boot-clock reading taken after the
// counter read (between the two bracketing readings here).
func TestDropResultStampsTheBootClock(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)

	el.handleRingbufDropResult(ringbufDropResult{total: 0, delta: 0})
	el.handleRingbufDropResult(ringbufDropResult{warning: "read failed"})
	if got := el.lastDropSeenBootNs.Load(); got != 0 {
		t.Fatalf("lastDropSeenBootNs = %d after polls without drops, want 0", got)
	}

	before := bootClockNs()
	el.handleRingbufDropResult(ringbufDropResult{total: 3, delta: 3})
	after := bootClockNs()
	if got := el.lastDropSeenBootNs.Load(); got < before || got > after {
		t.Fatalf("lastDropSeenBootNs = %d, want within [%d, %d]", got, before, after)
	}
}

// TestRunTraceSetupTrustsRenameRecordsBeforeTheStart pins the wiring in
// ior.go: the trust is handed to the event loop exactly once, after the factory
// that wires the drop counter (trustRenameRecords reads dropSrc) and before the
// start signal, after which the loop may already consume records. Structural,
// like the other setup tests: the setup cannot run unprivileged. The call sits
// in applyProbeCapabilities; capabilityCall checks all of the above through
// it and fails the test otherwise.
func TestRunTraceSetupTrustsRenameRecordsBeforeTheStart(t *testing.T) {
	if call := capabilityCall(t, "trustRenameRecords"); call == nil {
		t.Fatal("trace setup does not hand the rename-record trust to the loop")
	}
}
