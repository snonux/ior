package internal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ior/internal/flags"
	"ior/internal/probemanager"
	"ior/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
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

func (p syscallFailingProgram) AttachRawTracepoint(name string) (probemanager.Link, error) {
	return recordingProgram{attacher: &p.attacher.recordingAttacher}.AttachRawTracepoint(name)
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
	got := warned.joined()
	if !strings.Contains(got, "no syscall probe attached") {
		t.Fatalf("warnings = %q, want the no-probe warning", got)
	}
	// The user may have emptied the selection in the probes modal, so the
	// startup flags would be a false lead here.
	if !strings.Contains(got, "probes modal (o/O)") || strings.Contains(got, "-tps") {
		t.Fatalf("warnings = %q, want the TUI wording that points at the probes modal, not at the flags", got)
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

// TestRequireAttachedProbesHeadlessClosesTheManager pins the manager close on
// the headless zero-probe error path. It detaches nothing (the manager holds
// no links), so the only observable effect is that the manager no longer
// accepts attaches: a leaked, still-open manager would let the caller that
// dropped it keep attaching through it.
func TestRequireAttachedProbesHeadlessClosesTheManager(t *testing.T) {
	attacher := &recordingAttacher{}
	mgr, release, err := attachTraceProbes(context.Background(), attacher, matchNothing, syscallPairNames("openat"), bpfSetupLog{status: failOnLog(t)})
	if err != nil {
		t.Fatalf("attachTraceProbes() = %v", err)
	}

	gotMgr, gotRelease, err := requireAttachedProbes(mgr, release, true, bpfSetupLog{warn: failOnLog(t)})

	if err == nil || gotMgr != nil || gotRelease != nil {
		t.Fatalf("requireAttachedProbes() = (%v, %v, %v), want an error and no manager", gotMgr, gotRelease != nil, err)
	}
	if attachErr := mgr.Attach("openat"); attachErr == nil {
		t.Fatal("the probe manager still accepts attaches after the failed headless setup: it was not closed")
	}
	if total, live := attacher.attached(); total != schedProbeLinks || live != 0 {
		t.Fatalf("attached %d links (%d live), want only the sched probes, all released", total, live)
	}
}

// emptySelectionConfig is a config whose -tps selection matches nothing, as
// it could arrive from a session restarted after the probes modal emptied it.
func emptySelectionConfig() flags.Config {
	return flags.Config{PidFilter: -1, TidFilter: -1, TracepointSelector: tracepoints.Selector{
		RestrictSyscalls: true, Syscalls: map[string]struct{}{},
	}}
}

// TestAttachSessionProbesModeDecidesErrorOrWarning covers the wiring of the
// headless flag (publisher == nil): with nothing selected the headless session
// fails and releases every probe, while the TUI session (non-nil publisher)
// keeps running, publishes its manager and surfaces a warning.
func TestAttachSessionProbesModeDecidesErrorOrWarning(t *testing.T) {
	t.Run("headless", func(t *testing.T) {
		attacher := &recordingAttacher{}
		mgr, release, err := attachSessionProbes(context.Background(), attacher, emptySelectionConfig(), nil, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t)})
		if err == nil || !strings.Contains(err.Error(), "no syscall probe attached") {
			t.Fatalf("error = %v, want the no-probe error", err)
		}
		if mgr != nil || release != nil {
			t.Fatal("a failed setup must not hand out a manager or release closure")
		}
		if _, live := attacher.attached(); live != 0 {
			t.Fatalf("%d links still attached after the failed headless setup", live)
		}
	})
	t.Run("tui", func(t *testing.T) {
		attacher := &recordingAttacher{}
		warned := &lineRecorder{}
		publisher := &probePublisherRecorder{}
		mgr, release, err := attachSessionProbes(context.Background(), attacher, emptySelectionConfig(), publisher, bpfSetupLog{status: failOnLog(t), warn: warned.log})
		if err != nil {
			t.Fatalf("TUI setup with no probes must not fail, got %v", err)
		}
		if mgr == nil || release == nil || len(publisher.published) != 1 || publisher.published[0] == nil {
			t.Fatalf("the TUI session must keep and publish its manager, published %v", publisher.published)
		}
		if !strings.Contains(warned.joined(), "probes modal") {
			t.Fatalf("warnings = %q, want the no-probe warning", warned.joined())
		}
		release()
		if _, live := attacher.attached(); live != 0 {
			t.Fatalf("%d links still attached after release", live)
		}
	})
}

// failLoad replaces the BPF load stage for the duration of a test, recording
// whether it ran. The stages before it (context and target checks) are then
// testable without root and a kernel.
func failLoad(t *testing.T) *bool {
	t.Helper()
	ran := new(bool)
	orig := loadSessionBPFModule
	loadSessionBPFModule = func(flags.Config, func(...any)) (*bpf.Module, string, error) {
		*ran = true
		return nil, "load object", errors.New("stub load failure")
	}
	t.Cleanup(func() { loadSessionBPFModule = orig })
	return ran
}

// TestSetupBPFModuleHeadlessRejectsMissingPidBeforeLoading pins that setup
// runs the -pid/-tid check in headless mode (nil publisher) and as an error,
// before the slow BPF load.
func TestSetupBPFModuleHeadlessRejectsMissingPidBeforeLoading(t *testing.T) {
	loaded := failLoad(t)
	cfg := flags.Config{PidFilter: 4000000, TidFilter: -1}

	_, _, release, err := setupBPFModule(context.Background(), cfg, nil, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t)})

	if err == nil || !strings.Contains(err.Error(), "no such process") {
		t.Fatalf("error = %v, want the nonexistent -pid error", err)
	}
	if *loaded {
		t.Fatal("the BPF module was loaded although the -pid scope is impossible")
	}
	release()
}

// TestSetupBPFModuleTUIWarnsAboutMissingPidAndContinues is the TUI side: the
// same scope is only a warning row and setup proceeds to the load stage (which
// the stub then fails, so the test does not need root).
func TestSetupBPFModuleTUIWarnsAboutMissingPidAndContinues(t *testing.T) {
	loaded := failLoad(t)
	warned := &lineRecorder{}
	publisher := &probePublisherRecorder{}
	cfg := flags.Config{PidFilter: 4000000, TidFilter: -1}

	_, _, _, err := setupBPFModule(context.Background(), cfg, publisher, bpfSetupLog{status: failOnLog(t), warn: warned.log})

	if err == nil || !strings.Contains(err.Error(), "stub load failure") || strings.Contains(err.Error(), "no such process") {
		t.Fatalf("error = %v, want setup to get past the target check to the load stage", err)
	}
	if !*loaded {
		t.Fatal("the TUI session stopped before the load stage")
	}
	if !strings.Contains(warned.joined(), "no such process") {
		t.Fatalf("warnings = %q, want the nonexistent -pid warning", warned.joined())
	}
	if len(publisher.published) != 0 {
		t.Fatalf("a failed setup published %d managers", len(publisher.published))
	}
}
