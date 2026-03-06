package flamegraph

import (
	"ior/internal/types"
	"strings"
)

// SeedTestFlameData populates a deterministic static flamegraph fixture.
// Intended for keyboard-navigation validation in TUI test-flame mode.
func SeedTestFlameData(liveTrie *LiveTrie) {
	if liveTrie == nil {
		return
	}
	for _, record := range testFlameRecords() {
		liveTrie.AddRecord(record)
	}
}

// SeedTestLiveFlameData populates deterministic synthetic data for a given live tick.
// The data shape stays navigable while branch weights shift by phase so the
// terminal flamegraph visibly changes over time.
func SeedTestLiveFlameData(liveTrie *LiveTrie, tick uint64) {
	if liveTrie == nil {
		return
	}
	phase := tick % 4
	for _, base := range testFlameRecords() {
		weight := liveTestWeight(base, phase)
		liveTrie.AddRecord(withTestFlameWeight(base, weight))
	}
}

func testFlameRecords() []IterRecord {
	return []IterRecord{
		newTestFlameRecord("api", "/srv/api/lib/http/client/read", 2001, 2201, types.SYS_ENTER_READ, 180),
		newTestFlameRecord("api", "/srv/api/lib/json/encode/write", 2001, 2201, types.SYS_ENTER_WRITE, 120),
		newTestFlameRecord("api", "/srv/api/storage/postgres/query/read", 2001, 2201, types.SYS_ENTER_READ, 240),
		newTestFlameRecord("api", "/srv/api/storage/postgres/commit/fsync", 2001, 2201, types.SYS_ENTER_FSYNC, 70),
		newTestFlameRecord("worker", "/srv/worker/queue/pop/read", 2002, 2202, types.SYS_ENTER_READ, 160),
		newTestFlameRecord("worker", "/srv/worker/queue/push/write", 2002, 2202, types.SYS_ENTER_WRITE, 145),
		newTestFlameRecord("worker", "/srv/worker/cache/redis/get/read", 2002, 2202, types.SYS_ENTER_READ, 95),
		newTestFlameRecord("worker", "/srv/worker/cache/redis/set/write", 2002, 2202, types.SYS_ENTER_WRITE, 90),
		newTestFlameRecord("ingest", "/srv/ingest/parser/csv/read", 2003, 2203, types.SYS_ENTER_READ, 110),
		newTestFlameRecord("ingest", "/srv/ingest/parser/csv/normalize/write", 2003, 2203, types.SYS_ENTER_WRITE, 80),
		newTestFlameRecord("ingest", "/srv/ingest/uploader/s3/put/writev", 2003, 2203, types.SYS_ENTER_WRITEV, 75),
		newTestFlameRecord("batch", "/srv/batch/jobs/report/open", 2004, 2204, types.SYS_ENTER_OPENAT, 55),
		newTestFlameRecord("batch", "/srv/batch/jobs/report/close", 2004, 2204, types.SYS_ENTER_CLOSE, 35),
		newTestFlameRecord("batch", "/srv/batch/jobs/report/rename", 2004, 2204, types.SYS_ENTER_RENAMEAT, 20),
	}
}

func newTestFlameRecord(comm, path string, pid, tid uint32, traceID types.TraceId, weight uint64) IterRecord {
	return IterRecord{
		Path:    path,
		TraceID: traceID,
		Comm:    comm,
		Pid:     pid,
		Tid:     tid,
		Cnt: Counter{
			Count:          weight,
			Duration:       weight * 1000,
			DurationToPrev: weight * 350,
			Bytes:          weight * 4096,
		},
	}
}

func withTestFlameWeight(record IterRecord, weight uint64) IterRecord {
	record.Cnt = Counter{
		Count:          weight,
		Duration:       weight * 1000,
		DurationToPrev: weight * 350,
		Bytes:          weight * 4096,
	}
	return record
}

func liveTestWeight(record IterRecord, phase uint64) uint64 {
	base := record.Cnt.Count
	multiplier := uint64(1)

	switch phase {
	case 0:
		if record.Comm == "api" {
			multiplier += 4
		}
		if strings.Contains(record.Path, "/lib/") {
			multiplier += 2
		}
	case 1:
		if record.Comm == "worker" {
			multiplier += 4
		}
		if strings.Contains(record.Path, "/queue/") {
			multiplier += 2
		}
	case 2:
		if record.Comm == "ingest" {
			multiplier += 4
		}
		if strings.Contains(record.Path, "/uploader/") || strings.Contains(record.Path, "/parser/") {
			multiplier += 2
		}
	case 3:
		if record.Comm == "batch" {
			multiplier += 4
		}
		if strings.Contains(record.Path, "/report/") {
			multiplier += 2
		}
	}

	if strings.Contains(record.Path, "/storage/") && phase%2 == 0 {
		multiplier++
	}
	if strings.Contains(record.Path, "/cache/") && phase%2 == 1 {
		multiplier++
	}
	return base * multiplier
}
