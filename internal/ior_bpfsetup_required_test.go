package internal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ior/internal/probemanager"
)

// syscallFailingAttacher attaches the sched/task probes but fails every
// syscall tracepoint, like a kernel that lacks all of them.
type syscallFailingAttacher struct{ recordingAttacher }

func (a *syscallFailingAttacher) GetProgram(string) (probemanager.Program, error) {
	return syscallFailingProgram{attacher: a}, nil
}

type syscallFailingProgram struct{ attacher *syscallFailingAttacher }

func (p syscallFailingProgram) AttachTracepoint(category, name string) (probemanager.Link, error) {
	if category == "syscalls" {
		return nil, errors.New("tracepoint not found")
	}
	return recordingProgram{attacher: &p.attacher.recordingAttacher}.AttachTracepoint(category, name)
}

func matchNothing(string) bool { return false }

// TestAttachRequiredTraceProbesHeadlessFailsWhenSelectionMatchesNothing is the
// regression test for -tps nonexistent: the run used to succeed with zero
// probes and idle for the whole -duration. Headless it must now be an error
// that says what to fix, with every probe (sched ones included) released.
func TestAttachRequiredTraceProbesHeadlessFailsWhenSelectionMatchesNothing(t *testing.T) {
	attacher := &recordingAttacher{}
	names := syscallPairNames("openat", "read")

	mgr, release, err := attachRequiredTraceProbes(context.Background(), attacher, matchNothing, names, true, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t)})

	if err == nil || !strings.Contains(err.Error(), "matches none of the 2 traceable syscalls") {
		t.Fatalf("error = %v, want the empty-selection diagnostic", err)
	}
	if mgr != nil || release != nil {
		t.Fatal("a failed setup must not hand out a manager or release closure")
	}
	if total, live := attacher.attached(); total != schedProbeLinks || live != 0 {
		t.Fatalf("attached %d links (%d live), want only the sched probes, all released", total, live)
	}
}

// TestAttachRequiredTraceProbesHeadlessFailsWhenEveryAttachFails covers the
// other cause of zero probes: a selection that matched but whose tracepoints
// all failed to attach. The message must blame the attach, not the selection.
func TestAttachRequiredTraceProbesHeadlessFailsWhenEveryAttachFails(t *testing.T) {
	attacher := &syscallFailingAttacher{}
	skipped := &lineRecorder{}

	_, _, err := attachRequiredTraceProbes(context.Background(), attacher, nil, syscallPairNames("openat", "read"), true, bpfSetupLog{status: skipped.log})

	if err == nil || !strings.Contains(err.Error(), "all 2 selected tracepoint pairs failed to attach") {
		t.Fatalf("error = %v, want the all-attaches-failed diagnostic", err)
	}
	if strings.Contains(err.Error(), "selection matches none") {
		t.Fatalf("error %q blames the selection although it matched", err)
	}
	if !strings.Contains(skipped.joined(), "skipping tracepoint for openat") {
		t.Fatalf("per-syscall skips must still be logged, got %q", skipped.joined())
	}
	if _, live := attacher.attached(); live != 0 {
		t.Fatalf("%d links still attached after the failed setup", live)
	}
}

// TestAttachRequiredTraceProbesTUIOnlyWarns pins the interactive policy: the
// probes modal can attach probes later (and a user may have switched all of
// them off), so zero probes keeps the session and surfaces a warning.
func TestAttachRequiredTraceProbesTUIOnlyWarns(t *testing.T) {
	attacher := &recordingAttacher{}
	warned := &lineRecorder{}

	mgr, release, err := attachRequiredTraceProbes(context.Background(), attacher, matchNothing, syscallPairNames("openat"), false, bpfSetupLog{status: failOnLog(t), warn: warned.log})

	if err != nil {
		t.Fatalf("TUI setup with no probes must not fail, got %v", err)
	}
	if mgr == nil || release == nil {
		t.Fatal("the session must keep its manager and release closure")
	}
	defer release()
	if !strings.Contains(warned.joined(), "no syscall probe attached") {
		t.Fatalf("warnings = %q, want the no-probe warning", warned.joined())
	}
}

// TestAttachRequiredTraceProbesAcceptsOneAttachedProbe is the negative case:
// a selection that attaches anything, headless or not, is neither an error nor
// a warning, and one failing sibling does not turn it into one.
func TestAttachRequiredTraceProbesAcceptsOneAttachedProbe(t *testing.T) {
	onlyRead := func(name string) bool { return strings.HasSuffix(name, "_read") }
	for _, headless := range []bool{true, false} {
		attacher := &recordingAttacher{}
		mgr, release, err := attachRequiredTraceProbes(context.Background(), attacher, onlyRead, syscallPairNames("openat", "read"), headless, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t)})
		if err != nil {
			t.Fatalf("headless=%v: unexpected error %v", headless, err)
		}
		if active, total := mgr.ActiveCount(); active != 1 || total != 2 {
			t.Fatalf("headless=%v: active/total = %d/%d, want 1/2", headless, active, total)
		}
		release()
	}
}
