package internal

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task xr2 benchmarks: what the comm resolver costs under thread churn.
//
// Reference numbers (amd64, -benchtime 20000x; see the xr2 annotation and the
// commit message for the full before/after):
//   - BenchmarkThreadChurnCommLookups/recheck (the pre-xr2 behaviour: every
//     newtask seed is re-read) ~1 lookup per thread, almost all ENOENT;
//     /trusted (rename probe attached, drops monitored) 0 lookups per thread.
//   - BenchmarkResolveCommOfGoneTid: one failing openat instead of an openat
//     plus a failing readlinkat.

// churnTidBase is far above any pid_max (at most 2^22), so /proc/<tid> never
// exists and every procfs lookup fails with ENOENT, like the lookup of a
// thread that has exited before a resolver worker got to it.
const churnTidBase = 0x70000000

// BenchmarkThreadChurnCommLookups replays the records of one short-lived
// thread per iteration through the raw path - its task_newtask record, one
// read pair, its exit record - against the real procfs resolver, and reports
// the procfs lookups it caused (lookups/op) and the process CPU time including
// the resolver workers (cpu-ns/op, from getrusage).
func BenchmarkThreadChurnCommLookups(b *testing.B) {
	for _, tc := range []struct {
		name    string
		trusted bool
	}{
		{"recheck", false},
		{"trusted", true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var lookups atomic.Int64
			resolver := newCommResolver(nil)
			resolver.resolveFn = func(ctx context.Context, tid uint32) (string, error) {
				lookups.Add(1)
				return resolveCommWithinCtx(ctx, tid)
			}
			el := mustNewEventLoop(b, eventLoopConfig{filter: globalfilter.Filter{}, commResolver: resolver})
			b.Cleanup(resolver.shutdown)
			el.renameRecordsTrusted = tc.trusted
			out := make(chan *event.Pair, 1)
			startCPU := processCPUNs(b)
			b.ReportAllocs()
			i := uint32(0)
			for b.Loop() {
				replayChurnThread(b, el, churnTidBase+i, out)
				i++
			}
			waitForLookupsToLand(b, resolver)
			b.ReportMetric(float64(lookups.Load())/float64(i), "lookups/op")
			b.ReportMetric(float64(processCPUNs(b)-startCPU)/float64(i), "cpu-ns/op")
		})
	}
}

// replayChurnThread feeds the records of one thread that is created, reads
// once and exits.
func replayChurnThread(b *testing.B, el *eventLoop, tid uint32, out chan *event.Pair) {
	b.Helper()
	const pid = churnTidBase - 1
	newtask := types.TaskNewtaskEvent{EventType: types.TASK_NEWTASK_EVENT, Time: defaulTime,
		Pid: pid, Tid: tid, CloneFlags: cloneFlagThread, CreatorPid: pid}
	copy(newtask.Comm[:], "churn")
	el.processRawEvent(mustBenchBytes(b, &newtask), out)
	el.processRawEvent(mustBenchBytes(b, &types.FdEvent{EventType: types.ENTER_FD_EVENT, TraceId: types.SYS_ENTER_READ,
		Time: defaulTime + 10, Pid: pid, Tid: tid, Fd: 3, SchemaVersion: types.FD_EVENT_SCHEMA_VERSION}), out)
	el.processRawEvent(mustBenchBytes(b, &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_READ,
		Time: defaulTime + 20, Pid: pid, Tid: tid, Ret: 0}), out)
	select {
	case ep := <-out:
		ep.Recycle()
	default:
		b.Fatal("read pair was not emitted")
	}
	el.processRawEvent(mustBenchBytes(b, &types.ProcessExitEvent{EventType: types.PROCESS_EXIT_EVENT,
		Time: defaulTime + 30, Pid: pid, Tid: tid}), out)
}

// waitForLookupsToLand waits until the resolver has no lookup in flight, so
// lookups/op and cpu-ns/op include the work the replay queued.
func waitForLookupsToLand(b *testing.B, r *commResolver) {
	b.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.RLock()
		inFlight := len(r.pending)
		r.mu.RUnlock()
		if inFlight == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	b.Fatal("comm lookups still in flight after 30s")
}

// processCPUNs is the user+system CPU time the whole process consumed so far.
func processCPUNs(b *testing.B) int64 {
	b.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		b.Fatal(err)
	}
	return ru.Utime.Nano() + ru.Stime.Nano()
}

// BenchmarkResolveCommOfGoneTid is the procfs cost of one lookup for a thread
// that has exited, the common outcome under churn.
func BenchmarkResolveCommOfGoneTid(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if comm, err := resolveCommFromProcWithError(churnTidBase); comm != "" || err != nil {
			b.Fatalf("resolve of a gone tid = %q, %v; want \"\", nil", comm, err)
		}
	}
}
