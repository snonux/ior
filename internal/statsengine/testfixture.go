package statsengine

import (
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// SeedTestStatsData populates a statsengine.Engine with a deterministic set of
// synthetic syscall pairs. It mirrors the comms and file layout of the static
// flamegraph fixture (internal/flamegraph/testfixture.go) so the demo stays
// coherent across views, and is intended to drive the stats dashboard in TUI
// test mode without requiring a live BPF tracer.
func SeedTestStatsData(e *Engine) {
	if e == nil {
		return
	}
	for _, pair := range testStatsPairs() {
		e.Ingest(pair)
	}
}

// testStatsSpec describes one synthetic syscall pair in a flat, readable form.
type testStatsSpec struct {
	traceID  types.TraceId
	retType  uint32
	ret      int64
	comm     string
	pid      uint32
	path     string
	bytes    uint64
	duration uint64
	gap      uint64
}

// testStatsPairs returns the deterministic catalog of synthetic pairs. The set
// spans multiple comms, several syscall families (FS reads/writes/opens/closes/
// fsync plus a few non-FS calls), distinct file paths, non-trivial timing and
// byte counts, and a handful of error returns so the error and latency columns
// populate.
func testStatsPairs() []*event.Pair {
	specs := []testStatsSpec{
		// api: HTTP and storage I/O with one read error.
		{types.SYS_ENTER_READ, types.READ_CLASSIFIED, 180, "api", 2001, "/srv/api/lib/http/client/read", 184320, 180000, 0},
		{types.SYS_ENTER_WRITE, types.WRITE_CLASSIFIED, 120, "api", 2001, "/srv/api/lib/json/encode/write", 122880, 120000, 60000},
		{types.SYS_ENTER_READ, types.READ_CLASSIFIED, 240, "api", 2001, "/srv/api/storage/postgres/query/read", 245760, 240000, 45000},
		{types.SYS_ENTER_READ, types.READ_CLASSIFIED, -5, "api", 2001, "/srv/api/storage/postgres/query/read", 0, 95000, 30000},
		{types.SYS_ENTER_FSYNC, types.UNCLASSIFIED, 0, "api", 2001, "/srv/api/storage/postgres/commit/fsync", 0, 70000, 25000},

		// worker: queue and cache traffic with one write error.
		{types.SYS_ENTER_READ, types.READ_CLASSIFIED, 160, "worker", 2002, "/srv/worker/queue/pop/read", 163840, 160000, 50000},
		{types.SYS_ENTER_WRITE, types.WRITE_CLASSIFIED, 145, "worker", 2002, "/srv/worker/queue/push/write", 148480, 145000, 40000},
		{types.SYS_ENTER_WRITE, types.WRITE_CLASSIFIED, -28, "worker", 2002, "/srv/worker/queue/push/write", 0, 210000, 35000},
		{types.SYS_ENTER_READ, types.READ_CLASSIFIED, 95, "worker", 2002, "/srv/worker/cache/redis/get/read", 97280, 95000, 20000},
		{types.SYS_ENTER_WRITE, types.WRITE_CLASSIFIED, 90, "worker", 2002, "/srv/worker/cache/redis/set/write", 92160, 90000, 18000},
		// Non-FS so the Non-IO tab has rows.
		{types.SYS_ENTER_EPOLL_WAIT, types.UNCLASSIFIED, 2, "worker", 2002, "", 0, 320000, 15000},

		// ingest: parsing and upload I/O.
		{types.SYS_ENTER_OPENAT, types.UNCLASSIFIED, 7, "ingest", 2003, "/srv/ingest/parser/csv/source", 0, 55000, 22000},
		{types.SYS_ENTER_READ, types.READ_CLASSIFIED, 110, "ingest", 2003, "/srv/ingest/parser/csv/read", 112640, 110000, 28000},
		{types.SYS_ENTER_WRITE, types.WRITE_CLASSIFIED, 80, "ingest", 2003, "/srv/ingest/parser/csv/normalize/write", 81920, 80000, 24000},
		{types.SYS_ENTER_WRITE, types.WRITE_CLASSIFIED, 75, "ingest", 2003, "/srv/ingest/uploader/s3/put/write", 76800, 75000, 21000},
		{types.SYS_ENTER_CLOSE, types.UNCLASSIFIED, 0, "ingest", 2003, "/srv/ingest/parser/csv/source", 0, 18000, 12000},

		// batch: report generation plus a few non-FS calls.
		{types.SYS_ENTER_OPENAT, types.UNCLASSIFIED, 9, "batch", 2004, "/srv/batch/jobs/report/open", 0, 55000, 26000},
		{types.SYS_ENTER_WRITE, types.WRITE_CLASSIFIED, 64, "batch", 2004, "/srv/batch/jobs/report/data", 65536, 64000, 23000},
		{types.SYS_ENTER_FSYNC, types.UNCLASSIFIED, -5, "batch", 2004, "/srv/batch/jobs/report/data", 0, 130000, 19000},
		{types.SYS_ENTER_CLOSE, types.UNCLASSIFIED, 0, "batch", 2004, "/srv/batch/jobs/report/open", 0, 35000, 14000},
		{types.SYS_ENTER_GETPID, types.UNCLASSIFIED, 2004, "batch", 2004, "", 0, 5000, 8000},
		{types.SYS_ENTER_POLL, types.UNCLASSIFIED, 1, "batch", 2004, "", 0, 90000, 17000},
	}

	pairs := make([]*event.Pair, 0, len(specs))
	for _, spec := range specs {
		pairs = append(pairs, newTestStatsPair(spec))
	}
	return pairs
}

// newTestStatsPair builds a single *event.Pair from a spec, matching the shape
// that Engine.Ingest consumes (see newEnginePair in engine_test.go).
func newTestStatsPair(spec testStatsSpec) *event.Pair {
	return &event.Pair{
		EnterEv:        &types.RetEvent{TraceId: spec.traceID, Pid: spec.pid, Tid: spec.pid},
		ExitEv:         &types.RetEvent{TraceId: spec.traceID, Pid: spec.pid, Tid: spec.pid, Ret: spec.ret, RetType: spec.retType},
		Comm:           spec.comm,
		Duration:       spec.duration,
		DurationToPrev: spec.gap,
		Bytes:          spec.bytes,
		File:           file.NewFd(3, spec.path, -1),
	}
}
