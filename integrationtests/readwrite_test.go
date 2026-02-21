package integrationtests

import "testing"

func TestReadwriteBasic(t *testing.T) {
	runScenario(t, "readwrite-basic", []ExpectedEvent{
		{
			PathContains: "rwfile.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "rwfile.txt",
			Tracepoint:   "enter_read",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwritePread(t *testing.T) {
	runScenario(t, "readwrite-pread", []ExpectedEvent{
		{
			PathContains: "preadfile.txt",
			Tracepoint:   "enter_pread64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwritePwrite(t *testing.T) {
	runScenario(t, "readwrite-pwrite", []ExpectedEvent{
		{
			PathContains: "pwritefile.txt",
			Tracepoint:   "enter_pwrite64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwriteReadv(t *testing.T) {
	runScenario(t, "readwrite-readv", []ExpectedEvent{
		{
			PathContains: "readvfile.txt",
			Tracepoint:   "enter_readv",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwriteWritev(t *testing.T) {
	runScenario(t, "readwrite-writev", []ExpectedEvent{
		{
			PathContains: "writevfile.txt",
			Tracepoint:   "enter_writev",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwriteWronlyRead(t *testing.T) {
	runScenario(t, "readwrite-wronly-read", []ExpectedEvent{
		{
			PathContains: "wronlyfile.txt",
			Tracepoint:   "enter_read",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwriteRdonlyWrite(t *testing.T) {
	runScenario(t, "readwrite-rdonly-write", []ExpectedEvent{
		{
			PathContains: "rdonlywritefile.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwritePreadInvalid(t *testing.T) {
	runScenario(t, "readwrite-pread-invalid", []ExpectedEvent{
		{
			PathContains: "preadinvalid.txt",
			Tracepoint:   "enter_pread64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestReadwritePwriteInvalid(t *testing.T) {
	runScenario(t, "readwrite-pwrite-invalid", []ExpectedEvent{
		{
			PathContains: "pwriteinvalid.txt",
			Tracepoint:   "enter_pwrite64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
