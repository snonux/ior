package internal

import (
	"slices"
	"testing"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/types"
)

// Tests for the restart_syscall fold in a run that samples restart_syscall
// itself (task s13, "Sampling" in eventloop_restart.go). A sampled-out
// restart_syscall is missing from the stream without any record lost, so the
// drop check of task p03 cannot see it; such a run does not hold -516 rows at
// all. The fold of every other run, including one that samples the
// interrupted syscall, must be what it was. Since task t13 the RESUME record
// keeps a sampled-out restart_syscall from handing the row a later one by
// itself (TestSampledOutRestartSyscallIsNotFoldedWithoutTheGuard in
// eventloop_restart_handled_test.go); the guard tested here stays on top.

// samplingConfig is a flags.Config with the given sampling rates on top of
// the built-in defaults of its output mode: a raw mode (-plain) promotes the
// aggregate-only defaults to 1, which is the same as having none; the TUI
// keeps futex and clock_gettime at 0, so its runs always sample something.
type samplingConfig struct {
	name     string
	plain    bool
	syscalls map[string]uint32
	families map[types.SyscallFamily]uint32
}

func (c samplingConfig) flags() flags.Config {
	cfg := flags.NewFlags()
	cfg.PlainMode = c.plain
	if !c.plain {
		cfg.DefaultSyscallSamplingRates = map[string]uint32{"futex": 0, "clock_gettime": 0}
	}
	for name, rate := range c.syscalls {
		cfg.SyscallSamplingRates[name] = rate
	}
	for family, rate := range c.families {
		cfg.SyscallFamilySamplingRates[family] = rate
	}
	return cfg
}

// samplingFixtures are the three kinds of run the restart folds know, each on
// a loop built from cfg's sampling configuration: no drop counter, a counter
// on which nothing is ever lost, and that counter with BPF's re-execution
// proof on. The guard must not depend on which.
func samplingFixtures(cfg flags.Config) map[string]func(*testing.T) *restartFixture {
	build := func(t *testing.T) *restartFixture {
		t.Helper()
		return newRestartFixtureFor(t, eventLoopConfig{aggregateIngestTraceIDs: buildAggregateIngestTraceIDs(cfg)})
	}
	return map[string]func(*testing.T) *restartFixture{
		"no drop counter": build,
		"drop counter that never moves": func(t *testing.T) *restartFixture {
			f := build(t)
			f.countDrops()
			return f
		},
		"re-execution proof on": func(t *testing.T) *restartFixture {
			f := build(t)
			f.countDrops()
			f.el.foldProvenRestarts(true, true)
			return f
		},
	}
}

// stoppedSleepThenRestart feeds a clock_nanosleep at base that exits -516
// 500ns later, BPF's RESUME record for the sleep's own restart_syscall at
// resumeAt, then a restart_syscall of the same thread from enterAt to exitAt
// returning ret, and returns every row the five records emitted. resumeAt is
// enterAt when the restart_syscall is the sleep's own, and earlier when that
// one was sampled out (RESUME is emitted before the sampling decision) and the
// restart_syscall that arrives is a later call's. Each record is processed
// 50ns after it was stamped when the fixture has a clock. The drop counter, if
// any, is never moved: nothing is lost in this stream.
func stoppedSleepThenRestart(f *restartFixture, base, resumeAt, enterAt, exitAt uint64, ret int64) []restartRow {
	f.t.Helper()
	feedAt := func(at uint64, raw []byte) []restartRow {
		if f.drops != nil {
			f.clockAt(at + 50)
		}
		return f.feed(raw)
	}
	rows := feedAt(base, f.sleepEnter(base, restartTid))
	rows = append(rows, feedAt(base+500, f.sleepExit(base+500, restartTid, -516))...)
	rows = append(rows, feedAt(resumeAt, f.resumeRecord(resumeAt, restartTid))...)
	rows = append(rows, feedAt(enterAt, f.restartEnter(enterAt, restartTid))...)
	return append(rows, feedAt(exitAt, f.restartExit(exitAt, restartTid, ret))...)
}

// TestSampledRestartSyscallNeverFoldsAStranger is the defect of task s13.
// Call A, a stopped sleep, is recorded; its restart_syscall is sampled out; a
// later stopped call B of the thread is sampled out too; B's restart_syscall
// is sampled in. What arrives is a -516 exit followed, on the same thread, by
// a restart_syscall (and, since task t13, the RESUME record of A's own
// restart_syscall in between) - with no record lost and a drop counter that
// never moves - and before the fix B's result
// and end time were folded into A's row. With restart_syscall sampled (by its
// own rate, by its family's, or aggregate-only in a mode that keeps the 0)
// the two rows stay apart, and A's row does not wait for anything.
func TestSampledRestartSyscallNeverFoldsAStranger(t *testing.T) {
	for _, cfg := range []samplingConfig{
		{name: "restart_syscall=2", plain: true, syscalls: map[string]uint32{"restart_syscall": 2}},
		{name: "Process=2", plain: true, families: map[types.SyscallFamily]uint32{types.FamilyProcess: 2}},
		{name: "Process=0 in the TUI", families: map[types.SyscallFamily]uint32{types.FamilyProcess: 0}},
	} {
		for kind, newFixture := range samplingFixtures(cfg.flags()) {
			t.Run(cfg.name+"/"+kind, func(t *testing.T) {
				f := newFixture(t)
				const laterEnter, laterExit = restartBase + 8000, restartBase + 9000
				rows := stoppedSleepThenRestart(f, restartBase, restartBase+1500, laterEnter, laterExit, -4)
				want := []restartRow{
					{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: restartBase, duration: 500,
						sleepNs: restartSleepNs},
					{name: "restart_syscall", tid: restartTid, ret: -4, enterTime: laterEnter,
						duration: laterExit - laterEnter, gap: laterEnter - restartBase - 500},
				}
				if !slices.Equal(rows, want) {
					t.Fatalf("rows = %+v, want the -516 row and the later call's restart_syscall apart %+v", rows, want)
				}
				f.requireNothingHeld()
				if f.el.numSyscalls != 2 {
					t.Fatalf("numSyscalls = %d, want 2", f.el.numSyscalls)
				}
			})
		}
	}
}

// TestSampledRestartSyscallRowIsNotHeld: in a run that samples
// restart_syscall the -516 row is emitted by its own exit, not by the tid's
// next record, and the tracker stays empty - there is no fold to wait for.
func TestSampledRestartSyscallRowIsNotHeld(t *testing.T) {
	cfg := samplingConfig{plain: true, syscalls: map[string]uint32{"restart_syscall": 2}}
	for kind, newFixture := range samplingFixtures(cfg.flags()) {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.feedNone(f.sleepEnter(restartBase, restartTid), "clock_nanosleep enter")
			row := f.feedOne(f.sleepExit(restartBase+500, restartTid, -516), "clock_nanosleep -516 exit")
			if row.name != "clock_nanosleep" || row.ret != -516 || row.duration != 500 {
				t.Fatalf("row = %+v, want the -516 sleep as it was", row)
			}
			f.requireNothingHeld()
		})
	}
}

// TestRestartSyscallAtRateOneStillFolds is the negative control: the guard is
// about restart_syscall's own effective rate and nothing else. A run that
// samples nothing, one that samples the interrupted syscall or its family,
// one whose explicit restart_syscall=1 overrides a sampled family, and a raw
// mode in which the family's 0 is promoted to 1 all emit every
// restart_syscall, so a stopped sleep is one row there.
func TestRestartSyscallAtRateOneStillFolds(t *testing.T) {
	for _, cfg := range []samplingConfig{
		{name: "nothing sampled", plain: true},
		{name: "TUI defaults"},
		{name: "restart_syscall=1", plain: true, syscalls: map[string]uint32{"restart_syscall": 1}},
		{name: "clock_nanosleep=4", plain: true, syscalls: map[string]uint32{"clock_nanosleep": 4}},
		{name: "Time=4", plain: true, families: map[types.SyscallFamily]uint32{types.FamilyTime: 4}},
		{name: "Process=5 restart_syscall=1", plain: true, syscalls: map[string]uint32{"restart_syscall": 1},
			families: map[types.SyscallFamily]uint32{types.FamilyProcess: 5}},
		{name: "Process=0 promoted in a raw mode", plain: true,
			families: map[types.SyscallFamily]uint32{types.FamilyProcess: 0}},
	} {
		for kind, newFixture := range samplingFixtures(cfg.flags()) {
			t.Run(cfg.name+"/"+kind, func(t *testing.T) {
				f := newFixture(t)
				rows := stoppedSleepThenRestart(f, restartBase, restartBase+1500, restartBase+1500, restartBase+3000, 0)
				requireFoldedSleep(t, rows, restartBase, "restart_syscall is at rate 1")
				f.requireNothingHeld()
				if f.el.numSyscalls != 1 {
					t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
				}
			})
		}
	}
}

// TestNewEventLoopKnowsWhetherRestartSyscallIsSampled pins the wiring: the
// loop a run builds from its flags (newEventLoopConfig, newEventLoop) tells
// the restart tracker that restart_syscall is sampled exactly when the rate
// BPF applies to it (buildSyscallSamplingRates, which is what
// applySyscallSamplingRates loads) is not 1.
func TestNewEventLoopKnowsWhetherRestartSyscallIsSampled(t *testing.T) {
	if family := types.SYS_ENTER_RESTART_SYSCALL.Family(); family != types.FamilyProcess {
		t.Fatalf("restart_syscall is in family %v; the family cases below assume Process", family)
	}
	process := func(rate uint32) map[types.SyscallFamily]uint32 {
		return map[types.SyscallFamily]uint32{types.FamilyProcess: rate}
	}
	restart := func(rate uint32) map[string]uint32 { return map[string]uint32{"restart_syscall": rate} }
	for _, tc := range []struct {
		cfg  samplingConfig
		want bool
	}{
		{samplingConfig{name: "unset, raw mode", plain: true}, false},
		{samplingConfig{name: "unset, TUI"}, false},
		{samplingConfig{name: "restart_syscall=2", plain: true, syscalls: restart(2)}, true},
		{samplingConfig{name: "restart_syscall=2, TUI", syscalls: restart(2)}, true},
		{samplingConfig{name: "restart_syscall=1", plain: true, syscalls: restart(1)}, false},
		{samplingConfig{name: "restart_syscall=0, raw mode keeps an explicit 0", plain: true, syscalls: restart(0)}, true},
		{samplingConfig{name: "Process=3", plain: true, families: process(3)}, true},
		{samplingConfig{name: "Process=1", plain: true, families: process(1)}, false},
		{samplingConfig{name: "Process=3 restart_syscall=1", plain: true, families: process(3), syscalls: restart(1)}, false},
		{samplingConfig{name: "Process=1 restart_syscall=4", plain: true, families: process(1), syscalls: restart(4)}, true},
		{samplingConfig{name: "Process=0, raw mode promotes it", plain: true, families: process(0)}, false},
		{samplingConfig{name: "Process=0, TUI", families: process(0)}, true},
		{samplingConfig{name: "another family", plain: true,
			families: map[types.SyscallFamily]uint32{types.FamilyTime: 10}}, false},
		{samplingConfig{name: "the interrupted syscall", plain: true,
			syscalls: map[string]uint32{"clock_nanosleep": 5}}, false},
	} {
		t.Run(tc.cfg.name, func(t *testing.T) {
			cfg := tc.cfg.flags()
			el := mustNewEventLoop(t, newEventLoopConfig(cfg))
			t.Cleanup(el.commResolver.shutdown)
			if el.restarts.restartSyscallSampled != tc.want {
				t.Fatalf("restartSyscallSampled = %t, want %t", el.restarts.restartSyscallSampled, tc.want)
			}
			rate, configured := buildSyscallSamplingRates(cfg)[types.SYS_ENTER_RESTART_SYSCALL]
			if atRateOne := !configured || rate == 1; atRateOne == tc.want {
				t.Fatalf("BPF is given rate %d (configured %t) for restart_syscall, but the guard is %t",
					rate, configured, tc.want)
			}
		})
	}
}

// TestSampledRestartSyscallHoldsOnlyReexecutedRows pins the guard in the
// tracker itself: with restart_syscall sampled a -516 row is not holdable,
// with or without BPF's re-execution proof, while the re-execution codes are
// held as before - their fold goes by BPF's RESUME record, not by
// restart_syscall.
func TestSampledRestartSyscallHoldsOnlyReexecutedRows(t *testing.T) {
	heldFor := func(tid uint32, ret int64) *heldRestart {
		return &heldRestart{pair: &event.Pair{
			EnterEv: &types.NullEvent{TraceId: types.SYS_ENTER_NANOSLEEP, Tid: tid},
			ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_NANOSLEEP, Tid: tid, Ret: ret},
		}}
	}
	for _, reexec := range []bool{false, true} {
		sampled := restartTracker{restartBlock: true, reexec: reexec, restartSyscallSampled: true}
		if sampled.hold(heldFor(1, -516)) {
			t.Fatalf("a -516 row was held although restart_syscall is sampled (reexec %t)", reexec)
		}
		for i, ret := range []int64{-512, -513, -514} {
			if got := sampled.hold(heldFor(uint32(i+2), ret)); got != reexec {
				t.Fatalf("hold(ret=%d) = %t with reexec %t; sampling restart_syscall must not change it", ret, got, reexec)
			}
		}
		unsampled := restartTracker{restartBlock: true, reexec: reexec}
		if !unsampled.hold(heldFor(1, -516)) {
			t.Fatalf("a -516 row was not held although restart_syscall is at rate 1 (reexec %t)", reexec)
		}
	}
}
