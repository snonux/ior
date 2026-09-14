package integrationtests

import (
	"syscall"
	"testing"
)

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

func TestSyncSyncFileRangeToEOF(t *testing.T) {
	runScenario(t, "sync-sync-file-range-to-eof", []ExpectedEvent{
		{
			PathContains: "syncrangeeoffile.txt",
			Tracepoint:   "enter_sync_file_range",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestSyncFsyncEbadf(t *testing.T) {
	runParquetErrorScenario(t, "sync-fsync-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "fsync",
		FD:      ptrTo(int32(99999)),
	}, nil)
}

func TestSyncFdatasyncEbadf(t *testing.T) {
	runParquetErrorScenario(t, "sync-fdatasync-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "fdatasync",
		FD:      ptrTo(int32(99999)),
	}, nil)
}

func TestSyncFileRangeEbadf(t *testing.T) {
	runParquetErrorScenario(t, "sync-file-range-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "sync_file_range",
		FD:      ptrTo(int32(99999)),
	}, nil)
}
