package internal

import (
	"bytes"
	"go/printer"
	"go/token"
	"testing"
)

// Task xr2 review: the inputs of the newtask trust - what turns it on (the
// rename probe's attach), what turns it off again (a drop counter that cannot
// be read), and the order the drop monitor publishes its stamp in. Each test
// here fails when the corresponding line in production code is removed or
// reordered; the decision itself is covered in
// eventloop_newtask_recheck_test.go.

// TestRenameAttachRecorderNotesOnlyTheRenameProbe pins the attach sink that
// turns the trust on: only the task_rename probe's announcement sets it, any
// other probe leaves it off, and a later announcement does not clear it.
func TestRenameAttachRecorderNotesOnlyTheRenameProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		announced []string
		want      bool
	}{
		{"nothing attached", nil, false},
		{"other sched probes", []string{"sched_process_exec", "task_newtask"}, false},
		{"a near miss", []string{taskRenameProbeName + "x"}, false},
		{"the rename probe", []string{taskRenameProbeName}, true},
		{"rename then others", []string{taskRenameProbeName, "sched_process_exit"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var recorder renameAttachRecorder
			note := recorder.note // the method value setupTraceInfraBPF hands out
			for _, name := range tc.announced {
				note(name)
			}
			if recorder.attached != tc.want {
				t.Fatalf("attached = %v after %q, want %v", recorder.attached, tc.announced, tc.want)
			}
		})
	}
}

// TestTraceSetupCarriesTheRenameAttachToTheLoop pins the rest of the chain,
// structurally because the setup cannot run unprivileged: setupTraceInfraBPF
// hands the recorder's note to BPF setup as the attached sink (the sink key
// itself is pinned by TestSetupTraceInfraWiresConsoleSinks) and copies its
// result into the infra, and runTraceSetup passes exactly that field to
// trustRenameRecords.
func TestTraceSetupCarriesTheRenameAttachToTheLoop(t *testing.T) {
	bpfDecl, _ := parseInternalFunction(t, "ior.go", "setupTraceInfraBPF")
	if !hasAssignment(bpfDecl, "noteAttached", "renameAttach", "note") {
		t.Fatal("setupTraceInfraBPF must set noteAttached := renameAttach.note")
	}
	const carry = "infra.renameProbeAttached = renameAttach.attached"
	found := false
	for _, statement := range bpfDecl.Body.List {
		var rendered bytes.Buffer
		if err := printer.Fprint(&rendered, token.NewFileSet(), statement); err != nil {
			t.Fatalf("render statement: %v", err)
		}
		found = found || rendered.String() == carry
	}
	if !found {
		t.Fatalf("setupTraceInfraBPF must carry the attach into the infra: %s", carry)
	}

	setupDecl, _ := parseInternalFunction(t, "ior.go", "runTraceSetup")
	calls := callsNamed(setupDecl, "trustRenameRecords")
	if len(calls) != 1 {
		t.Fatalf("runTraceSetup calls trustRenameRecords %d times, want once", len(calls))
	}
	assertCallArguments(t, calls[0], []string{"infra.renameProbeAttached"})
}

// TestFailedDropReadKeepsTheNewtaskRecheck: while the drop counter cannot be
// read a lost rename would not show up as a drop, so a trusted seed keeps its
// read; the next successful read restores the trust.
func TestFailedDropReadKeepsTheNewtaskRecheck(t *testing.T) {
	el, procfs := newRecheckEventLoop(t, true, procfsComm)
	el.handleRingbufDropResult(ringbufDropResult{warning: "read failed"})
	seedNewTask(t, el, newTaskStart, inheritedComm)
	if got := useNewTask(t, el); got != procfsComm {
		t.Fatalf("comm = %q, want the procfs read's %q", got, procfsComm)
	}
	requireReads(t, procfs, 1)

	el.handleRingbufDropResult(ringbufDropResult{total: 0, delta: 0})
	if el.provisionalSeedNeedsRecheck(newTaskStart + 1) {
		t.Fatal("a successful drop read must restore the trust")
	}
}

// TestDropStampIsStoredBeforeTheSweepIsRequested pins the store order in
// requestCommSweepAfterDrop. If commRefreshPending became visible first, the
// event loop could apply the sweep and then seed a newtask record reserved
// before the drop while lastDropSeenBootNs still held the older stamp: that
// seed would escape both the sweep and the time check. The injected clock
// observes the flag at the moment the stamp is taken, which is before the flag
// is raised only in the right order.
func TestDropStampIsStoredBeforeTheSweepIsRequested(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	const stamp = 12345
	flagSeenAtStamp := []bool{}
	el.dropStampClock = func() uint64 {
		flagSeenAtStamp = append(flagSeenAtStamp, el.commRefreshPending.Load())
		return stamp
	}

	el.handleRingbufDropResult(ringbufDropResult{total: 2, delta: 2})
	if len(flagSeenAtStamp) != 1 || flagSeenAtStamp[0] {
		t.Fatalf("sweep flag at stamp time = %v, want one stamp taken before the flag",
			flagSeenAtStamp)
	}
	if !el.commRefreshPending.Load() || el.lastDropSeenBootNs.Load() != stamp {
		t.Fatalf("after the drop: flag %v, stamp %d; want true, %d",
			el.commRefreshPending.Load(), el.lastDropSeenBootNs.Load(), stamp)
	}
}
