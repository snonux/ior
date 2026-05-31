package integrationtests

import "testing"

func TestReadwriteBasic(t *testing.T) {
	const payloadLen = uint64(len("hello from ioworkload"))
	result, _ := runScenarioResult(t, "readwrite-basic", []ExpectedEvent{
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
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "rwfile.txt",
		Tracepoint:   "enter_write",
		Comm:         "ioworkload",
	}, payloadLen)
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "rwfile.txt",
		Tracepoint:   "enter_read",
		Comm:         "ioworkload",
	}, payloadLen)
}

func TestReadwritePread(t *testing.T) {
	// pread64 returns the number of bytes read (READ_CLASSIFIED), so a
	// successful positional read must attribute the payload byte count
	// end-to-end, mirroring the pwrite64 byte-count assertion below.
	const payloadLen = uint64(len("pread test data"))
	result, _ := runScenarioResult(t, "readwrite-pread", []ExpectedEvent{
		{
			PathContains: "preadfile.txt",
			Tracepoint:   "enter_pread64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "preadfile.txt",
		Tracepoint:   "enter_pread64",
		Comm:         "ioworkload",
	}, payloadLen)
}

func TestReadwritePwrite(t *testing.T) {
	result, _ := runScenarioResult(t, "readwrite-pwrite", []ExpectedEvent{
		{
			PathContains: "pwritefile.txt",
			Tracepoint:   "enter_pwrite64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "pwritefile.txt",
		Tracepoint:   "enter_pwrite64",
		Comm:         "ioworkload",
	}, 1)
}

func TestReadwritePreadv(t *testing.T) {
	// preadv is the positional vectored read sibling of pread64/readv and is
	// READ_CLASSIFIED, so a successful read must attribute the payload bytes
	// end-to-end.
	const payloadLen = uint64(len("preadv test data"))
	result, _ := runScenarioResult(t, "readwrite-preadv", []ExpectedEvent{
		{
			PathContains: "preadvfile.txt",
			Tracepoint:   "enter_preadv",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "preadvfile.txt",
		Tracepoint:   "enter_preadv",
		Comm:         "ioworkload",
	}, payloadLen)
}

func TestReadwritePreadv2(t *testing.T) {
	// preadv2 is the positional vectored read variant with flags; like preadv
	// it is READ_CLASSIFIED and must attribute the payload bytes end-to-end.
	const payloadLen = uint64(len("preadv2 test data"))
	result, _ := runScenarioResult(t, "readwrite-preadv2", []ExpectedEvent{
		{
			PathContains: "preadv2file.txt",
			Tracepoint:   "enter_preadv2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "preadv2file.txt",
		Tracepoint:   "enter_preadv2",
		Comm:         "ioworkload",
	}, payloadLen)
}

func TestReadwriteReadv(t *testing.T) {
	result, _ := runScenarioResult(t, "readwrite-readv", []ExpectedEvent{
		{
			PathContains: "readvfile.txt",
			Tracepoint:   "enter_readv",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "readvfile.txt",
		Tracepoint:   "enter_readv",
		Comm:         "ioworkload",
	}, 1)
}

func TestReadwriteWritev(t *testing.T) {
	result, _ := runScenarioResult(t, "readwrite-writev", []ExpectedEvent{
		{
			PathContains: "writevfile.txt",
			Tracepoint:   "enter_writev",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesAtLeast(t, result, ExpectedEvent{
		PathContains: "writevfile.txt",
		Tracepoint:   "enter_writev",
		Comm:         "ioworkload",
	}, 1)
}

func TestReadwriteWronlyRead(t *testing.T) {
	result, _ := runScenarioResult(t, "readwrite-wronly-read", []ExpectedEvent{
		{
			PathContains: "wronlyfile.txt",
			Tracepoint:   "enter_read",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesEqual(t, result, ExpectedEvent{
		PathContains: "wronlyfile.txt",
		Tracepoint:   "enter_read",
		Comm:         "ioworkload",
	}, 0)
	assertEventBytesReasonable(t, result, ExpectedEvent{
		PathContains: "wronlyfile.txt",
		Tracepoint:   "enter_read",
		Comm:         "ioworkload",
	})
}

func TestReadwriteRdonlyWrite(t *testing.T) {
	result, _ := runScenarioResult(t, "readwrite-rdonly-write", []ExpectedEvent{
		{
			PathContains: "rdonlywritefile.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesEqual(t, result, ExpectedEvent{
		PathContains: "rdonlywritefile.txt",
		Tracepoint:   "enter_write",
		Comm:         "ioworkload",
	}, 0)
	assertEventBytesReasonable(t, result, ExpectedEvent{
		PathContains: "rdonlywritefile.txt",
		Tracepoint:   "enter_write",
		Comm:         "ioworkload",
	})
}

func TestReadwritePreadInvalid(t *testing.T) {
	result, _ := runScenarioResult(t, "readwrite-pread-invalid", []ExpectedEvent{
		{
			PathContains: "preadinvalid.txt",
			Tracepoint:   "enter_pread64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesEqual(t, result, ExpectedEvent{
		PathContains: "preadinvalid.txt",
		Tracepoint:   "enter_pread64",
		Comm:         "ioworkload",
	}, 0)
	assertEventBytesReasonable(t, result, ExpectedEvent{
		PathContains: "preadinvalid.txt",
		Tracepoint:   "enter_pread64",
		Comm:         "ioworkload",
	})
}

func TestReadwritePwriteInvalid(t *testing.T) {
	result, _ := runScenarioResult(t, "readwrite-pwrite-invalid", []ExpectedEvent{
		{
			PathContains: "pwriteinvalid.txt",
			Tracepoint:   "enter_pwrite64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	assertEventBytesEqual(t, result, ExpectedEvent{
		PathContains: "pwriteinvalid.txt",
		Tracepoint:   "enter_pwrite64",
		Comm:         "ioworkload",
	}, 0)
	assertEventBytesReasonable(t, result, ExpectedEvent{
		PathContains: "pwriteinvalid.txt",
		Tracepoint:   "enter_pwrite64",
		Comm:         "ioworkload",
	})
}

func TestReadwriteReadahead(t *testing.T) {
	// readahead(2) is KindFd / UNCLASSIFIED: despite its ssize_t prototype it
	// returns 0/-1 and transfers no bytes to userspace, so the tracer must
	// attribute zero bytes (not misread the 0/-1 return as a byte count) while
	// still capturing the fd (args[0]) on enter and timing the syscall.
	result, _ := runScenarioResult(t, "readwrite-readahead", []ExpectedEvent{
		{
			PathContains: "readaheadfile.txt",
			Tracepoint:   "enter_readahead",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
	exp := ExpectedEvent{
		PathContains: "readaheadfile.txt",
		Tracepoint:   "enter_readahead",
		Comm:         "ioworkload",
	}
	// UNCLASSIFIED: no byte count is attributed for a successful readahead.
	assertEventBytesEqual(t, result, exp, 0)
	// Timing is captured end-to-end (enter/exit paired into a duration).
	assertEventDurationPositive(t, result, exp)
}

func TestReadwriteReadaheadEbadf(t *testing.T) {
	// readahead on an invalid fd fails with EBADF, but ior still captures the
	// enter_readahead tracepoint because arguments are read on syscall entry
	// before the kernel returns the error. The UNCLASSIFIED -1 return must not
	// be attributed as bytes.
	result, _ := runScenarioResult(t, "readwrite-readahead-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_readahead",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
	assertEventBytesEqual(t, result, ExpectedEvent{
		Tracepoint: "enter_readahead",
		Comm:       "ioworkload",
	}, 0)
}

func assertEventBytesAtLeast(t *testing.T, result TestResult, exp ExpectedEvent, minBytes uint64) {
	t.Helper()
	var matched bool
	var totalBytes uint64
	for _, rec := range result.Records {
		if !matchesExpectation(rec, exp) {
			continue
		}
		matched = true
		totalBytes += rec.Cnt.Bytes
	}
	if !matched {
		t.Fatalf("expected event not found while asserting bytes: %+v", exp)
	}
	if totalBytes < minBytes {
		t.Fatalf("bytes for %+v too small: got=%d want>=%d", exp, totalBytes, minBytes)
	}
}

func assertEventBytesEqual(t *testing.T, result TestResult, exp ExpectedEvent, wantBytes uint64) {
	t.Helper()
	var matched bool
	var totalBytes uint64
	for _, rec := range result.Records {
		if !matchesExpectation(rec, exp) {
			continue
		}
		matched = true
		totalBytes += rec.Cnt.Bytes
	}
	if !matched {
		t.Fatalf("expected event not found while asserting bytes: %+v", exp)
	}
	if totalBytes != wantBytes {
		t.Fatalf("bytes for %+v mismatch: got=%d want=%d", exp, totalBytes, wantBytes)
	}
}

func assertEventBytesReasonable(t *testing.T, result TestResult, exp ExpectedEvent) {
	t.Helper()
	const maxReasonableBytes = 1 << 20 // 1MiB is far above any bytes used in these scenarios.
	var matched bool
	for _, rec := range result.Records {
		if !matchesExpectation(rec, exp) {
			continue
		}
		matched = true
		if rec.Cnt.Bytes > maxReasonableBytes {
			t.Fatalf("unreasonable bytes for %+v: got=%d (possible underflow/sign issue)", exp, rec.Cnt.Bytes)
		}
	}
	if !matched {
		t.Fatalf("expected event not found while asserting byte range: %+v", exp)
	}
}

func assertEventDurationPositive(t *testing.T, result TestResult, exp ExpectedEvent) {
	t.Helper()
	var matched bool
	var totalDuration uint64
	for _, rec := range result.Records {
		if !matchesExpectation(rec, exp) {
			continue
		}
		matched = true
		totalDuration += rec.Cnt.Duration
	}
	if !matched {
		t.Fatalf("expected event not found while asserting duration: %+v", exp)
	}
	if totalDuration == 0 {
		t.Fatalf("duration for %+v is zero", exp)
	}
}
