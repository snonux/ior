package internal

import (
	"bytes"
	"go/printer"
	"go/token"
	"testing"
)

// Task 103: what turns the re-execution fold on. BPF's RESUME record is a
// proof only while the signal_deliver probe sees every handler delivered to
// an interrupted task, the sched_process_exit probe makes BPF forget a dying
// task, and the drop counter can vouch for the stream, so the fold must be on
// exactly when all three hold. Each test here fails when the corresponding line in production
// code is removed; the fold itself is covered in
// eventloop_restart_reexec_test.go.

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

// TestTraceSetupCarriesTheSignalAttachToTheLoop pins the rest of the chain,
// structurally because the setup cannot run unprivileged: setupTraceInfraBPF
// hands the hand-probe recorder's note to BPF setup, that note reaches the
// signal and exit recorders, their results are copied into the infra, and
// runTraceSetup passes exactly those fields to foldReexecutedRestarts, once.
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

	setupDecl, _ := parseInternalFunction(t, "ior.go", "runTraceSetup")
	calls := callsNamed(setupDecl, "foldReexecutedRestarts")
	if len(calls) != 1 {
		t.Fatalf("runTraceSetup calls foldReexecutedRestarts %d times, want once", len(calls))
	}
	assertCallArguments(t, calls[0], []string{"infra.signalProbeAttached", "infra.exitProbeAttached"})
}

// TestFoldReexecutedRestartsNeedsTheWholeProof: the loop holds -512/-513/-514
// rows only when told both probes attached and with a drop counter to read,
// and never by default. Each missing piece is a way to a wrong fold: without
// signal_deliver a program's own retry is announced, without
// sched_process_exit a recycled tid inherits a dead task's pending call, and
// without the drop counter lost records go unnoticed.
func TestFoldReexecutedRestartsNeedsTheWholeProof(t *testing.T) {
	counter := ringbufDropSourceFunc(func() (uint64, error) { return 0, nil })
	for _, tc := range []struct {
		name         string
		signal, exit bool
		drops        ringbufDropSource
		want         bool
	}{
		{"everything", true, true, counter, true},
		{"no signal probe", false, true, counter, false},
		{"no exit probe", true, false, counter, false},
		{"no drop counter", true, true, nil, false},
		{"nothing", false, false, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
			t.Cleanup(el.commResolver.shutdown)
			if el.restarts.reexec {
				t.Fatal("a fresh event loop folds re-executions without being told the probes attached")
			}
			el.dropSrc = tc.drops
			el.foldReexecutedRestarts(tc.signal, tc.exit)
			if el.restarts.reexec != tc.want {
				t.Fatalf("reexec = %t, want %t", el.restarts.reexec, tc.want)
			}
			el.foldReexecutedRestarts(false, false)
			if el.restarts.reexec {
				t.Fatal("foldReexecutedRestarts(false, false) left the fold on")
			}
		})
	}
}
