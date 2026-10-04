package tui

import (
	"context"
	"testing"

	"ior/internal/flags"
)

// startupConfig returns a default config with the given -pid/-tid values,
// the way the CLI would have parsed them.
func startupConfig(pid, tid int) flags.Config {
	cfg := flags.NewFlags()
	cfg.PidFilter = pid
	cfg.TidFilter = tid
	return cfg
}

// firstStartupRequest drives a picker-skipping run model the way Bubble Tea
// does (Init, then the requested startup trace) and returns the TraceRequest
// the starter received for the first session.
func firstStartupRequest(t *testing.T, cfg flags.Config) (*Model, TraceRequest) {
	t.Helper()
	starter := newRecordingStarter()
	m := newRunModel(cfg, starter.start)
	t.Cleanup(m.tracer.stop)

	runCmdAsync(initTraceCmd(t, m))
	starter.next(t)
	return m, starter.nextRequest(t)
}

// TestResolveStartupPIDFilters pins the pid/tid resolution table. The bug it
// guards: the tid was forced to -1 whenever an attach pid existed, so
// `ior -pid P -tid T` (whose attach pid is the configured -pid) traced the whole
// process. A tid is only dropped when the attach pid is a different process
// than the one the -tid was given for.
func TestResolveStartupPIDFilters(t *testing.T) {
	cases := []struct {
		name             string
		initialPID, pid  int
		tid              int
		wantPID, wantTID int
	}{
		{"pid and tid together keep both", 1234, 1234, 1240, 1234, 1240},
		{"tid alone is kept", -1, -1, 1240, -1, 1240},
		{"pid alone", 1234, 1234, -1, 1234, -1},
		{"nothing given", -1, -1, -1, -1, -1},
		{"different attach pid clears the tid", 7, 1234, 1240, 7, -1},
		{"attach pid without configured pid clears the tid", 7, -1, 1240, 7, -1},
		{"non-positive values normalise to -1", 0, 0, 0, -1, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid, tid := resolveStartupPIDFilters(tc.initialPID, tc.pid, tc.tid)
			if pid != tc.wantPID || tid != tc.wantTID {
				t.Fatalf("resolveStartupPIDFilters(%d, %d, %d) = (%d, %d), want (%d, %d)",
					tc.initialPID, tc.pid, tc.tid, pid, tid, tc.wantPID, tc.wantTID)
			}
		})
	}
}

// TestNewRunModelKeepsTidWithPid is the end-to-end regression for
// `ior -pid P -tid T`: the first TraceRequest must carry both predicates, not
// just the pid.
func TestNewRunModelKeepsTidWithPid(t *testing.T) {
	m, req := firstStartupRequest(t, startupConfig(1234, 1240))

	if m.proc.pid != 1234 || m.proc.tid != 1240 {
		t.Fatalf("model pid/tid = %d/%d, want 1234/1240", m.proc.pid, m.proc.tid)
	}
	if req.Filter == nil || req.Filter.PID == nil || req.Filter.PID.Value != 1234 {
		t.Fatalf("first request filter = %+v, want PID 1234", req.Filter)
	}
	if req.Filter.TID == nil || req.Filter.TID.Value != 1240 {
		t.Fatalf("first request filter TID = %+v, want 1240: the thread was dropped and the whole process is traced", req.Filter.TID)
	}
}

// TestNewRunModelTidAloneSkipsPickerAndTracesThread covers `ior -tid T`: it
// used to open the PID picker, whose result discarded the tid. It must start on
// the dashboard and trace just that thread, like headless mode.
func TestNewRunModelTidAloneSkipsPickerAndTracesThread(t *testing.T) {
	m, req := firstStartupRequest(t, startupConfig(-1, 1240))

	if m.router.current() != ScreenDashboard {
		t.Fatalf("a -tid must start on the dashboard, got %v", m.router.current())
	}
	if req.Filter == nil || req.Filter.TID == nil || req.Filter.TID.Value != 1240 {
		t.Fatalf("first request filter = %+v, want TID 1240", req.Filter)
	}
	if req.Filter.PID != nil {
		t.Fatalf("first request filter PID = %+v, want none: only the thread was named", req.Filter.PID)
	}
}

// TestNewRunModelWithoutPidOrTidOpensPicker is the negative case: with neither
// flag there is nothing to attach to, so the picker opens and no trace starts.
func TestNewRunModelWithoutPidOrTidOpensPicker(t *testing.T) {
	m := newRunModel(startupConfig(-1, -1), func(context.Context, TraceRequest) error { return nil })

	if m.router.current() != ScreenPIDPicker || m.attaching {
		t.Fatalf("startup = screen %v attaching %v, want an idle picker", m.router.current(), m.attaching)
	}
	if cmdEmits[initialTraceStartMsg](m.Init()) {
		t.Fatal("Init requested a startup trace without an attach target")
	}
}

// TestNewModelWithConfigAttachPidOverridesConfiguredTid keeps the old rule for
// the case it was written for: an attach pid that is not the configured -pid
// starts a trace of that process alone, without the other process's -tid.
func TestNewModelWithConfigAttachPidOverridesConfiguredTid(t *testing.T) {
	m := NewModelWithConfig(startupConfig(1234, 1240), 7, func(context.Context, TraceRequest) error { return nil })

	if m.proc.pid != 7 || m.proc.tid != -1 {
		t.Fatalf("model pid/tid = %d/%d, want 7/-1", m.proc.pid, m.proc.tid)
	}
	if f := m.filters.current(); f.TID != nil {
		t.Fatalf("startup filter TID = %+v, want none", f.TID)
	}
}

// TestPickedPidReplacesStartupTid pins that the startup tid seeds only the
// first session: once the user picks another process, the thread they started
// with no longer applies. It checks the model state, the live filter stack
// and the TraceRequest the second session actually receives, because the
// request is what decides whether the new process is traced whole or just one
// (foreign) thread.
func TestPickedPidReplacesStartupTid(t *testing.T) {
	starter := newRecordingStarter()
	m := newRunModel(startupConfig(-1, 1240), starter.start)
	t.Cleanup(m.tracer.stop)

	// First session: -tid alone traces just that thread.
	runCmdAsync(initTraceCmd(t, m))
	starter.next(t)
	if first := starter.nextRequest(t); first.Filter == nil || first.Filter.TID == nil || first.Filter.TID.Value != 1240 {
		t.Fatalf("first request filter = %+v, want TID 1240", first.Filter)
	}

	next, cmd := m.Update(PidSelectedMsg{Pid: 99})
	updated := next.(*Model)
	if updated.proc.pid != 99 || updated.proc.tid != -1 {
		t.Fatalf("model pid/tid after picking = %d/%d, want 99/-1", updated.proc.pid, updated.proc.tid)
	}
	if f := updated.filters.current(); f.TID != nil {
		t.Fatalf("filter stack TID after picking = %+v, want cleared", f.TID)
	}

	// Second session: the new process is traced whole, without the old tid.
	runCmdAsync(cmd)
	starter.next(t)
	req := starter.nextRequest(t)
	if req.Filter == nil || req.Filter.PID == nil || req.Filter.PID.Value != 99 {
		t.Fatalf("second request filter = %+v, want PID 99", req.Filter)
	}
	if req.Filter.TID != nil {
		t.Fatalf("second request filter TID = %+v, want none: the startup thread leaked into the picked process", req.Filter.TID)
	}
}
