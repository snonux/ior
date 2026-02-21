package integrationtests

import "testing"

func TestSyncBasic(t *testing.T) {
	runScenario(t, "sync-basic", []ExpectedEvent{
		{
			PathContains: "syncfile.txt",
			Tracepoint:   "enter_fsync",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestSyncFdatasync(t *testing.T) {
	runScenario(t, "sync-fdatasync", []ExpectedEvent{
		{
			PathContains: "fdatasyncfile.txt",
			Tracepoint:   "enter_fdatasync",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestSyncSync(t *testing.T) {
	runScenario(t, "sync-sync", []ExpectedEvent{
		{
			Tracepoint: "enter_sync",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestSyncSyncFileRange(t *testing.T) {
	runScenario(t, "sync-sync-file-range", []ExpectedEvent{
		{
			PathContains: "syncrangefile.txt",
			Tracepoint:   "enter_sync_file_range",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestSyncFsyncEbadf(t *testing.T) {
	runScenario(t, "sync-fsync-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_fsync",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestSyncFdatasyncEbadf(t *testing.T) {
	runScenario(t, "sync-fdatasync-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_fdatasync",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestSyncFileRangeEbadf(t *testing.T) {
	runScenario(t, "sync-file-range-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_sync_file_range",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
