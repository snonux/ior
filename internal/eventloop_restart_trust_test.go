package internal

import (
	"bytes"
	"go/printer"
	"go/token"
	"testing"
)

// Tasks 103 and t13: what turns the restart folds on. BPF's RESUME record is a
// proof only while the signal_deliver probe sees every handler delivered to
// an interrupted task and the sched_process_exit probe makes BPF forget a
// dying task, so -516 rows are held exactly when both attached; the
// re-execution fold of -512/-513/-514 also needs the drop counter to vouch for
// the stream. Each test here fails when the corresponding line in production
// code is removed; the folds themselves are covered in
// eventloop_restart_reexec_test.go, eventloop_restart_test.go and
// eventloop_restart_handled_test.go.

// TestSignalAttachRecorderNotesOnlyTheSignalProbe pins the attach sink: only
// the signal_deliver probe's announcement sets it. The restart fold's second
// probe (rt_sigreturn) must not, since without signal_deliver a program's own
// retry after EINTR would be folded.
func TestSignalAttachRecorderNotesOnlyTheSignalProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		announced []string
		want      bool
	}{
		{"nothing attached", nil, false},
		{"other hand probes", []string{"sched_process_exec", taskRenameProbeName, restartSigreturnProbeName}, false},
		{"a near miss", []string{signalDeliverProbeName + "x"}, false},
		{"the signal probe", []string{signalDeliverProbeName}, true},
		{"signal then others", []string{signalDeliverProbeName, restartSigreturnProbeName}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var recorder signalAttachRecorder
			for _, name := range tc.announced {
				recorder.note(name)
			}
			if recorder.attached != tc.want {
				t.Fatalf("attached = %v after %q, want %v", recorder.attached, tc.announced, tc.want)
			}
		})
	}
}

// TestExitAttachRecorderNotesOnlyTheExitProbe pins the second attach sink the
// fold depends on: only the sched_process_exit probe's announcement sets it.
// Set by any other probe, a run whose exit probe failed would fold although
// BPF never forgets a dead task, and a recycled tid's first syscall could be
// folded into the dead task's interrupted row.
func TestExitAttachRecorderNotesOnlyTheExitProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		announced []string
		want      bool
	}{
		{"nothing attached", nil, false},
		{"other hand probes", []string{"sched_process_exec", taskRenameProbeName, signalDeliverProbeName, restartSigreturnProbeName}, false},
		{"a near miss", []string{processExitProbeName + "x"}, false},
		{"the exit probe", []string{processExitProbeName}, true},
		{"exit then others", []string{processExitProbeName, signalDeliverProbeName}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var recorder exitAttachRecorder
			for _, name := range tc.announced {
				recorder.note(name)
			}
			if recorder.attached != tc.want {
				t.Fatalf("attached = %v after %q, want %v", recorder.attached, tc.announced, tc.want)
			}
		})
	}
}

// TestExitProbeAnnouncesItsRecorderName: the name the exit probe announces on
// attach is the one its recorder listens for.
func TestExitProbeAnnouncesItsRecorderName(t *testing.T) {
	var announced []string
	release := attachProcessExitProbe(&fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}}, bpfSetupLog{attached: func(name string) {
		announced = append(announced, name)
	}})
	defer release()
	if len(announced) != 1 || announced[0] != processExitProbeName {
		t.Fatalf("attachProcessExitProbe announced %q, want [%q]", announced, processExitProbeName)
	}
}

// TestExecAttachRecorderNotesOnlyTheExecProbe pins the attach sink of task
// v13: only the sched_process_exec probe's announcement sets it, and the
// probe announces the name the recorder listens for. Set by any other probe,
// a run without exec records would refuse to pair every non-leader exec's
// exit with its enter for want of a counted drop (eventLoop.lostExecRecord).
func TestExecAttachRecorderNotesOnlyTheExecProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		announced []string
		want      bool
	}{
		{"nothing attached", nil, false},
		{"other hand probes", []string{processExitProbeName, taskRenameProbeName, signalDeliverProbeName, restartSigreturnProbeName}, false},
		{"a near miss", []string{processExecProbeName + "x"}, false},
		{"the exec probe", []string{processExecProbeName}, true},
		{"exec then others", []string{processExecProbeName, processExitProbeName}, true},
	} {
		var hand handProbeAttachRecorder
		for _, name := range tc.announced {
			hand.note(name)
		}
		if hand.exec.attached != tc.want {
			t.Fatalf("%s: attached = %v after %q, want %v", tc.name, hand.exec.attached, tc.announced, tc.want)
		}
	}
	var announced []string
	release := attachProcessExecProbe(&fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}}, bpfSetupLog{attached: func(name string) {
		announced = append(announced, name)
	}})
	defer release()
	if len(announced) != 1 || announced[0] != processExecProbeName {
		t.Fatalf("attachProcessExecProbe announced %q, want [%q]", announced, processExecProbeName)
	}
}

// TestTraceSetupCarriesTheExecAttachToTheLoop pins the rest of that chain
// structurally, like the test below does for the fold's probes: the
// recorder's result is copied into the infra and runTraceSetup passes
// exactly that field to trustExecRecords, once.
func TestTraceSetupCarriesTheExecAttachToTheLoop(t *testing.T) {
	bpfDecl, _ := parseInternalFunction(t, "ior.go", "setupTraceInfraBPF")
	var body bytes.Buffer
	if err := printer.Fprint(&body, token.NewFileSet(), bpfDecl.Body); err != nil {
		t.Fatalf("render setupTraceInfraBPF: %v", err)
	}
	if want := "infra.execProbeAttached = handAttach.exec.attached"; !bytes.Contains(body.Bytes(), []byte(want)) {
		t.Fatalf("setupTraceInfraBPF must contain %q", want)
	}
	// Once, through applyProbeCapabilities (capabilityCall).
	assertCallArguments(t, capabilityCall(t, "trustExecRecords"), []string{"infra.execProbeAttached"})
}

// TestTraceSetupCarriesTheSignalAttachToTheLoop pins the rest of the chain,
// structurally because the setup cannot run unprivileged: setupTraceInfraBPF
// hands the hand-probe recorder's note to BPF setup, that note reaches the
// signal and exit recorders, their results are copied into the infra, and
// runTraceSetup passes exactly those fields to foldProvenRestarts, once.
func TestTraceSetupCarriesTheSignalAttachToTheLoop(t *testing.T) {
	bpfDecl, _ := parseInternalFunction(t, "ior.go", "setupTraceInfraBPF")
	var body bytes.Buffer
	if err := printer.Fprint(&body, token.NewFileSet(), bpfDecl.Body); err != nil {
		t.Fatalf("render setupTraceInfraBPF: %v", err)
	}
	for _, want := range []string{"noteAttached := handAttach.note", "infra.signalProbeAttached = handAttach.signal.attached",
		"infra.exitProbeAttached = handAttach.exit.attached"} {
		if !bytes.Contains(body.Bytes(), []byte(want)) {
			t.Fatalf("setupTraceInfraBPF must contain %q", want)
		}
	}
	var hand handProbeAttachRecorder
	hand.note(signalDeliverProbeName)
	if !hand.signal.attached || hand.rename.attached || hand.exit.attached {
		t.Fatalf("handProbeAttachRecorder.note(signal_deliver): signal=%t rename=%t exit=%t, want only signal",
			hand.signal.attached, hand.rename.attached, hand.exit.attached)
	}
	hand.note(processExitProbeName)
	if !hand.exit.attached {
		t.Fatal("handProbeAttachRecorder.note(sched_process_exit) did not reach the exit recorder")
	}

	// Once, through applyProbeCapabilities (capabilityCall).
	assertCallArguments(t, capabilityCall(t, "foldProvenRestarts"),
		[]string{"infra.signalProbeAttached", "infra.exitProbeAttached"})
}

// TestFoldProvenRestartsNeedsTheWholeProof: the loop holds -512/-513/-514
// rows only when told both probes attached and with a drop counter to read,
// -516 rows (restartBlock) when told both probes attached, with or without a
// counter, and neither by default. Each missing piece is a way to a wrong
// fold: without signal_deliver a program's own retry is announced (and, after
// a handler that siglongjmps out of a -516 call, a later call's
// restart_syscall), without sched_process_exit a recycled tid inherits a dead
// task's pending call, and without the drop counter lost records go
// unnoticed, which only the restart_syscall fold accepts.
func TestFoldProvenRestartsNeedsTheWholeProof(t *testing.T) {
	counter := ringbufDropSourceFunc(func() (uint64, error) { return 0, nil })
	for _, tc := range []struct {
		name         string
		signal, exit bool
		drops        ringbufDropSource
		want         bool
		wantBlock    bool
	}{
		{"everything", true, true, counter, true, true},
		{"no signal probe", false, true, counter, false, false},
		{"no exit probe", true, false, counter, false, false},
		{"no drop counter", true, true, nil, false, true},
		{"only the signal probe, no counter", true, false, nil, false, false},
		{"only the exit probe, no counter", false, true, nil, false, false},
		{"nothing", false, false, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
			t.Cleanup(el.commResolver.shutdown)
			if el.restarts.reexec || el.restarts.restartBlock {
				t.Fatal("a fresh event loop folds restarted calls without being told the probes attached")
			}
			el.dropSrc = tc.drops
			el.foldProvenRestarts(tc.signal, tc.exit)
			if el.restarts.reexec != tc.want || el.restarts.restartBlock != tc.wantBlock {
				t.Fatalf("reexec = %t restartBlock = %t, want %t and %t",
					el.restarts.reexec, el.restarts.restartBlock, tc.want, tc.wantBlock)
			}
			el.foldProvenRestarts(false, false)
			if el.restarts.reexec || el.restarts.restartBlock {
				t.Fatal("foldProvenRestarts(false, false) left a fold on")
			}
		})
	}
}
