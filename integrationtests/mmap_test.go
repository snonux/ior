package integrationtests

import "testing"

func TestMmapBasic(t *testing.T) {
	runScenario(t, "mmap-basic", []ExpectedEvent{
		{
			PathContains: "mmapfile.txt",
			Tracepoint:   "enter_mmap",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestMmapMsyncSync(t *testing.T) {
	runScenario(t, "mmap-msync-sync", []ExpectedEvent{
		{
			PathContains: "msyncfile.txt",
			Tracepoint:   "enter_mmap",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint: "enter_msync",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestMmapMsyncInvalidFlags(t *testing.T) {
	runScenario(t, "mmap-msync-invalid-flags", []ExpectedEvent{
		{
			PathContains: "msyncinvalidfile.txt",
			Tracepoint:   "enter_mmap",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint: "enter_msync",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
