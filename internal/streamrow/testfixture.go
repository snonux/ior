package streamrow

// SeedTestStreamData fills a RingBuffer with deterministic synthetic stream
// rows. It is shipped in the production binary so the TUI test-stream mode has
// stable content for rows/filter/search/select/export validation. The data
// mirrors the comms and paths used by the flamegraph and stats fixtures.
func SeedTestStreamData(buf *RingBuffer) {
	if buf == nil {
		return
	}
	for _, row := range testStreamRows() {
		buf.Push(row)
	}
}

// testStreamRows builds the ordered slice of synthetic rows. Seq and TimeNs are
// assigned monotonically so insertion order, gaps, and latencies stay stable
// across runs. Several rows carry IsError with a negative RetVal so error
// filtering and search have matches.
func testStreamRows() []Row {
	specs := testStreamSpecs()
	rows := make([]Row, 0, len(specs))
	var timeNs uint64 = 1_000_000_000
	for i, spec := range specs {
		timeNs += spec.gapNs
		rows = append(rows, newTestStreamRow(uint64(i+1), timeNs, spec))
	}
	return rows
}

// testStreamSpec captures the varying fields of one synthetic row. Stable
// per-comm metadata (PID/TID/FD) is derived in newTestStreamRow.
type testStreamSpec struct {
	comm       string
	syscall    string
	family     string
	fileName   string
	oldName    string
	durationNs uint64
	gapNs      uint64
	bytes      uint64
	retVal     int64
	isError    bool
}

// newTestStreamRow materialises a Row from a spec, deriving PID/TID/FD from the
// comm so every process keeps a consistent identity across its rows.
func newTestStreamRow(seq, timeNs uint64, spec testStreamSpec) Row {
	pid, tid, fd := testStreamIdentity(spec.comm, spec.syscall)
	return Row{
		Seq:        seq,
		TimeNs:     timeNs,
		Syscall:    spec.syscall,
		Family:     spec.family,
		Comm:       spec.comm,
		PID:        pid,
		TID:        tid,
		FileName:   spec.fileName,
		OldName:    spec.oldName,
		DurationNs: spec.durationNs,
		GapNs:      spec.gapNs,
		Bytes:      spec.bytes,
		RetVal:     spec.retVal,
		IsError:    spec.isError,
		FD:         fd,
	}
}

// testStreamIdentity returns the deterministic PID/TID/FD for a comm. Syscalls
// without a descriptor (epoll_wait, nanosleep) report UnknownFD.
func testStreamIdentity(comm, syscall string) (pid, tid uint32, fd int32) {
	switch comm {
	case "api":
		pid, tid, fd = 2001, 2201, 7
	case "worker":
		pid, tid, fd = 2002, 2202, 9
	case "ingest":
		pid, tid, fd = 2003, 2203, 11
	case "batch":
		pid, tid, fd = 2004, 2204, 13
	default:
		pid, tid, fd = 2000, 2200, 3
	}
	switch syscall {
	case "epoll_wait", "nanosleep", "futex":
		fd = UnknownFD
	}
	return pid, tid, fd
}

// testStreamSpecs returns the ~40 synthetic row specifications spanning four
// comms, FS and non-FS families, distinct paths, varied latencies/byte counts,
// and a handful of error rows.
func testStreamSpecs() []testStreamSpec {
	return []testStreamSpec{
		{comm: "api", syscall: "openat", family: "FS", fileName: "/srv/api/conf/app.yaml", durationNs: 18_400, gapNs: 1_200, bytes: 0, retVal: 7},
		{comm: "api", syscall: "read", family: "FS", fileName: "/srv/api/conf/app.yaml", durationNs: 42_100, gapNs: 2_300, bytes: 4096, retVal: 4096},
		{comm: "api", syscall: "read", family: "FS", fileName: "/srv/api/storage/postgres/socket", durationNs: 240_900, gapNs: 5_700, bytes: 8192, retVal: 8192},
		{comm: "api", syscall: "write", family: "FS", fileName: "/srv/api/log/access.log", durationNs: 31_500, gapNs: 1_900, bytes: 512, retVal: 512},
		{comm: "api", syscall: "fsync", family: "FS", fileName: "/srv/api/log/access.log", durationNs: 71_300, gapNs: 3_100, bytes: 0, retVal: 0},
		{comm: "api", syscall: "openat", family: "FS", fileName: "/srv/api/secrets/missing.pem", durationNs: 9_800, gapNs: 1_400, bytes: 0, retVal: -2, isError: true},
		{comm: "api", syscall: "epoll_wait", family: "Polling", fileName: "", durationNs: 1_204_000, gapNs: 6_500, bytes: 0, retVal: 1},
		{comm: "api", syscall: "close", family: "FS", fileName: "/srv/api/conf/app.yaml", durationNs: 5_200, gapNs: 900, bytes: 0, retVal: 0},

		{comm: "worker", syscall: "read", family: "FS", fileName: "/srv/worker/queue/pop", durationNs: 160_400, gapNs: 4_200, bytes: 16384, retVal: 16384},
		{comm: "worker", syscall: "write", family: "FS", fileName: "/srv/worker/queue/push", durationNs: 145_700, gapNs: 3_800, bytes: 16384, retVal: 16384},
		{comm: "worker", syscall: "read", family: "FS", fileName: "/srv/worker/cache/redis.sock", durationNs: 95_100, gapNs: 2_600, bytes: 2048, retVal: 2048},
		{comm: "worker", syscall: "write", family: "FS", fileName: "/srv/worker/cache/redis.sock", durationNs: 90_400, gapNs: 2_400, bytes: 2048, retVal: 2048},
		{comm: "worker", syscall: "futex", family: "IPC", fileName: "", durationNs: 512_000, gapNs: 7_900, bytes: 0, retVal: 0},
		{comm: "worker", syscall: "write", family: "FS", fileName: "/srv/worker/queue/dead", durationNs: 12_300, gapNs: 1_500, bytes: 0, retVal: -28, isError: true},
		{comm: "worker", syscall: "openat", family: "FS", fileName: "/srv/worker/data/chunk-001.bin", durationNs: 22_900, gapNs: 1_700, bytes: 0, retVal: 9},
		{comm: "worker", syscall: "close", family: "FS", fileName: "/srv/worker/data/chunk-001.bin", durationNs: 6_100, gapNs: 1_000, bytes: 0, retVal: 0},

		{comm: "ingest", syscall: "openat", family: "FS", fileName: "/srv/ingest/incoming/2026-06-11.csv", durationNs: 27_600, gapNs: 2_100, bytes: 0, retVal: 11},
		{comm: "ingest", syscall: "read", family: "FS", fileName: "/srv/ingest/incoming/2026-06-11.csv", durationNs: 110_300, gapNs: 3_300, bytes: 65536, retVal: 65536},
		{comm: "ingest", syscall: "write", family: "FS", fileName: "/srv/ingest/normalized/2026-06-11.parquet", durationNs: 80_500, gapNs: 2_900, bytes: 32768, retVal: 32768},
		{comm: "ingest", syscall: "writev", family: "FS", fileName: "/srv/ingest/uploader/s3-part-01", durationNs: 75_800, gapNs: 2_700, bytes: 1048576, retVal: 1048576},
		{comm: "ingest", syscall: "read", family: "FS", fileName: "/srv/ingest/incoming/corrupt.csv", durationNs: 14_200, gapNs: 1_600, bytes: 0, retVal: -5, isError: true},
		{comm: "ingest", syscall: "fsync", family: "FS", fileName: "/srv/ingest/normalized/2026-06-11.parquet", durationNs: 88_900, gapNs: 3_400, bytes: 0, retVal: 0},
		{comm: "ingest", syscall: "nanosleep", family: "Time", fileName: "", durationNs: 1_000_000, gapNs: 9_100, bytes: 0, retVal: 0},
		{comm: "ingest", syscall: "close", family: "FS", fileName: "/srv/ingest/incoming/2026-06-11.csv", durationNs: 5_900, gapNs: 1_100, bytes: 0, retVal: 0},

		{comm: "batch", syscall: "openat", family: "FS", fileName: "/srv/batch/jobs/report.tmp", durationNs: 19_700, gapNs: 1_800, bytes: 0, retVal: 13},
		{comm: "batch", syscall: "write", family: "FS", fileName: "/srv/batch/jobs/report.tmp", durationNs: 54_200, gapNs: 2_500, bytes: 24576, retVal: 24576},
		{comm: "batch", syscall: "fsync", family: "FS", fileName: "/srv/batch/jobs/report.tmp", durationNs: 64_800, gapNs: 3_000, bytes: 0, retVal: 0},
		{comm: "batch", syscall: "renameat2", family: "FS", fileName: "/srv/batch/jobs/report.final", oldName: "/srv/batch/jobs/report.tmp", durationNs: 21_300, gapNs: 1_900, bytes: 0, retVal: 0},
		{comm: "batch", syscall: "close", family: "FS", fileName: "/srv/batch/jobs/report.final", durationNs: 4_700, gapNs: 900, bytes: 0, retVal: 0},
		{comm: "batch", syscall: "openat", family: "FS", fileName: "/srv/batch/jobs/locked.db", durationNs: 11_100, gapNs: 1_300, bytes: 0, retVal: -13, isError: true},
		{comm: "batch", syscall: "read", family: "FS", fileName: "/srv/batch/input/ledger.dat", durationNs: 132_600, gapNs: 4_000, bytes: 49152, retVal: 49152},
		{comm: "batch", syscall: "write", family: "FS", fileName: "/srv/batch/output/summary.json", durationNs: 47_900, gapNs: 2_200, bytes: 8192, retVal: 8192},

		{comm: "api", syscall: "read", family: "FS", fileName: "/srv/api/storage/postgres/socket", durationNs: 198_300, gapNs: 5_100, bytes: 8192, retVal: 8192},
		{comm: "api", syscall: "write", family: "FS", fileName: "/srv/api/log/error.log", durationNs: 28_400, gapNs: 1_700, bytes: 256, retVal: 256},
		{comm: "worker", syscall: "read", family: "FS", fileName: "/srv/worker/queue/pop", durationNs: 151_900, gapNs: 4_300, bytes: 16384, retVal: 16384},
		{comm: "worker", syscall: "fsync", family: "FS", fileName: "/srv/worker/data/chunk-001.bin", durationNs: 69_500, gapNs: 3_200, bytes: 0, retVal: 0},
		{comm: "ingest", syscall: "writev", family: "FS", fileName: "/srv/ingest/uploader/s3-part-02", durationNs: 79_100, gapNs: 2_800, bytes: 1048576, retVal: 1048576},
		{comm: "batch", syscall: "write", family: "FS", fileName: "/srv/batch/output/summary.json", durationNs: 41_200, gapNs: 2_100, bytes: 4096, retVal: 4096},
		{comm: "batch", syscall: "fsync", family: "FS", fileName: "/srv/batch/output/summary.json", durationNs: 73_600, gapNs: 3_300, bytes: 0, retVal: -5, isError: true},
		{comm: "batch", syscall: "close", family: "FS", fileName: "/srv/batch/input/ledger.dat", durationNs: 5_400, gapNs: 1_000, bytes: 0, retVal: 0},
	}
}
