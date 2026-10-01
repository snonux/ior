package internal

import (
	"bytes"
	"go/printer"
	"go/token"
	"testing"
)

// Task 103: what turns the re-execution fold on. BPF's RESUME record is a
// proof only while the signal_deliver probe sees every handler delivered to
// an interrupted task, so the fold must be on exactly when that probe
// attached. Each test here fails when the corresponding line in production
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

// TestTraceSetupCarriesTheSignalAttachToTheLoop pins the rest of the chain,
// structurally because the setup cannot run unprivileged: setupTraceInfraBPF
// hands the hand-probe recorder's note to BPF setup, that note reaches the
// signal recorder, its result is copied into the infra, and runTraceSetup
// passes exactly that field to foldReexecutedRestarts, once.
func TestTraceSetupCarriesTheSignalAttachToTheLoop(t *testing.T) {
	bpfDecl, _ := parseInternalFunction(t, "ior.go", "setupTraceInfraBPF")
	var body bytes.Buffer
	if err := printer.Fprint(&body, token.NewFileSet(), bpfDecl.Body); err != nil {
		t.Fatalf("render setupTraceInfraBPF: %v", err)
	}
	for _, want := range []string{"noteAttached := handAttach.note", "infra.signalProbeAttached = handAttach.signal.attached"} {
		if !bytes.Contains(body.Bytes(), []byte(want)) {
			t.Fatalf("setupTraceInfraBPF must contain %q", want)
		}
	}
	var hand handProbeAttachRecorder
	hand.note(signalDeliverProbeName)
	if !hand.signal.attached || hand.rename.attached {
		t.Fatalf("handProbeAttachRecorder.note(signal_deliver): signal=%t rename=%t, want true and false",
			hand.signal.attached, hand.rename.attached)
	}

	setupDecl, _ := parseInternalFunction(t, "ior.go", "runTraceSetup")
	calls := callsNamed(setupDecl, "foldReexecutedRestarts")
	if len(calls) != 1 {
		t.Fatalf("runTraceSetup calls foldReexecutedRestarts %d times, want once", len(calls))
	}
	assertCallArguments(t, calls[0], []string{"infra.signalProbeAttached"})
}

// TestFoldReexecutedRestartsFollowsTheProbe: the loop holds -512/-513/-514
// rows exactly when told the probe attached, and never by default.
func TestFoldReexecutedRestartsFollowsTheProbe(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	if el.restarts.reexec {
		t.Fatal("a fresh event loop folds re-executions without being told the probe attached")
	}
	el.foldReexecutedRestarts(true)
	if !el.restarts.reexec {
		t.Fatal("foldReexecutedRestarts(true) did not turn the fold on")
	}
	el.foldReexecutedRestarts(false)
	if el.restarts.reexec {
		t.Fatal("foldReexecutedRestarts(false) left the fold on")
	}
}
