package integrationtests

import (
	"syscall"
	"testing"
)

func TestUnlinkBasic(t *testing.T) {
	runScenario(t, "unlink-basic", []ExpectedEvent{
		{
			PathContains: "unlinkme.txt",
			Tracepoint:   "enter_unlink",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestUnlinkUnlinkat(t *testing.T) {
	runScenario(t, "unlink-unlinkat", []ExpectedEvent{
		{
			PathContains: "unlinkat-file.txt",
			Tracepoint:   "enter_unlinkat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestUnlinkRmdir(t *testing.T) {
	runScenario(t, "unlink-rmdir", []ExpectedEvent{
		{
			PathContains: "rmdir-me",
			Tracepoint:   "enter_rmdir",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestUnlinkEnoent(t *testing.T) {
	runParquetErrorScenario(t, "unlink-enoent", syscall.ENOENT, ExpectedRow{
		FileContains: "unlink-enoent-missing.txt",
		Syscall:      "unlink",
	}, nil)
}

func TestUnlinkRmdirNotempty(t *testing.T) {
	runScenario(t, "unlink-rmdir-notempty", []ExpectedEvent{
		{
			PathContains: "rmdir-notempty",
			Tracepoint:   "enter_rmdir",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestUnlinkUnlinkatEnoent(t *testing.T) {
	runParquetErrorScenario(t, "unlink-unlinkat-enoent", syscall.ENOENT, ExpectedRow{
		FileContains: "unlinkat-enoent-missing.txt",
		Syscall:      "unlinkat",
	}, nil)
}
