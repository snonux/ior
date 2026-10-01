package internal

import (
	"context"
	"testing"

	"ior/internal/event"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// recycledStatsPid is the PID the kernel hands from a dead process to a new
// one in the tests below.
const recycledStatsPid = 2000

// statsTestFileComms labels each pair by the file it touched, standing in for
// the comm resolver: the first process ("a") only opens /a, its successor on
// the same PID ("b") only opens /b.
var statsTestFileComms = map[string]string{"/a": "a", "/b": "b"}

// runStatsExitScenario wires a real stats engine into an event loop the way
// the TUI does (engine as aggregate sink, print callback ingesting every pair
// synchronously), feeds raw records through el.run in order and returns the
// engine's process rows.
func runStatsExitScenario(t *testing.T, raws [][]byte) []statsengine.ProcessSnapshot {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	el.SetAggregateSink(engine)
	el.SetPrintCallback(func(ep *event.Pair) {
		ep.Comm = statsTestFileComms[rowFile(ep)]
		engine.Ingest(ep)
		ep.Recycle()
	})

	rawCh := make(chan []byte, len(raws))
	for _, raw := range raws {
		rawCh <- raw
	}
	close(rawCh)
	el.run(context.Background(), rawCh)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	return snap.Processes()
}

// openAccess returns the raw enter and exit records of one access() call by
// the leader of recycledStatsPid.
func openAccess(t *testing.T, at uint64, pathname string) [][]byte {
	t.Helper()
	_, enter := makeEnterPathEvent(t, at, recycledStatsPid, recycledStatsPid, pathname, types.SYS_ENTER_ACCESS)
	_, exit := makeExitRetEvent(t, at+1, recycledStatsPid, recycledStatsPid, types.SYS_EXIT_ACCESS, 0)
	return [][]byte{enter, exit}
}

// recycledPidExitCase is one way the first process of recycledStatsPid can
// end between its two opens and the second process's three.
type recycledPidExitCase struct {
	name string
	exit func(t *testing.T, at uint64) []byte
	want []statsengine.ProcessSnapshot // PID, Lifetime, Comm, Syscalls only
}

// recycledPidExitCases lists the group-dead, thread and legacy exit records
// and the process rows each must leave.
func recycledPidExitCases() []recycledPidExitCase {
	return []recycledPidExitCase{
		{
			name: "group dead exit retires the row",
			exit: func(t *testing.T, at uint64) []byte {
				return makeProcessExitEvent(t, at, recycledStatsPid, recycledStatsPid)
			},
			want: []statsengine.ProcessSnapshot{
				{PID: recycledStatsPid, Lifetime: 1, Comm: "b", Syscalls: 3},
				{PID: recycledStatsPid, Lifetime: 0, Comm: "a", Syscalls: 2},
			},
		},
		{
			name: "thread exit keeps the row",
			exit: func(t *testing.T, at uint64) []byte {
				return makeThreadExitEvent(t, at, recycledStatsPid, recycledStatsPid+1)
			},
			// One merged row: the leader's latest comm labels it, exactly
			// as for an exec, and nothing is lost.
			want: []statsengine.ProcessSnapshot{
				{PID: recycledStatsPid, Lifetime: 0, Comm: "b", Syscalls: 5},
			},
		},
		{
			name: "legacy exit record keeps the row",
			exit: func(t *testing.T, at uint64) []byte {
				// The legacy layout is the current one minus group_dead
				// and reserved.
				return makeThreadExitEvent(t, at, recycledStatsPid, recycledStatsPid+1)[:24]
			},
			want: []statsengine.ProcessSnapshot{
				{PID: recycledStatsPid, Lifetime: 0, Comm: "b", Syscalls: 5},
			},
		},
	}
}

// TestGroupDeadExitSplitsRecycledPidStatsRows is the end-to-end regression
// test for task ro2: a group-dead sched_process_exit must end the PID's row in
// the stats engine, so the next process handed the PID gets its own row and
// label instead of merging into the dead one's under the new comm. A thread
// exit (group_dead clear) must not split the row, and neither may the legacy
// 24-byte record of a pre-group_dead IOR_BPF_OBJECT, which cannot say whether
// the process died (task gp2 review): retiring on it would split a live
// multi-threaded process into one row per exited thread.
func TestGroupDeadExitSplitsRecycledPidStatsRows(t *testing.T) {
	for _, tt := range recycledPidExitCases() {
		t.Run(tt.name, func(t *testing.T) {
			var raws [][]byte
			at := uint64(1000)
			for range 2 {
				raws = append(raws, openAccess(t, at, "/a")...)
				at += 10
			}
			raws = append(raws, tt.exit(t, at))
			for range 3 {
				at += 10
				raws = append(raws, openAccess(t, at, "/b")...)
			}

			assertProcessRows(t, runStatsExitScenario(t, raws), tt.want)
		})
	}
}

// TestGroupDeadExitOfUntracedPidLeavesStatsAlone checks that the exit of a
// process that never produced a pair (e.g. forwarded by the -tid group-dead
// bypass) is a no-op for the stats engine.
func TestGroupDeadExitOfUntracedPidLeavesStatsAlone(t *testing.T) {
	raws := openAccess(t, 1000, "/a")
	raws = append(raws, makeProcessExitEvent(t, 1010, recycledStatsPid+7, recycledStatsPid+7))
	raws = append(raws, openAccess(t, 1020, "/a")...)

	assertProcessRows(t, runStatsExitScenario(t, raws), []statsengine.ProcessSnapshot{
		{PID: recycledStatsPid, Lifetime: 0, Comm: "a", Syscalls: 2},
	})
}

// assertProcessRows compares the identity and count of each process row.
func assertProcessRows(t *testing.T, got, want []statsengine.ProcessSnapshot) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d process rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.PID != w.PID || g.Lifetime != w.Lifetime || g.Comm != w.Comm || g.Syscalls != w.Syscalls {
			t.Fatalf("row %d = {PID:%d Lifetime:%d Comm:%q Syscalls:%d}, want {PID:%d Lifetime:%d Comm:%q Syscalls:%d}",
				i, g.PID, g.Lifetime, g.Comm, g.Syscalls, w.PID, w.Lifetime, w.Comm, w.Syscalls)
		}
	}
}
