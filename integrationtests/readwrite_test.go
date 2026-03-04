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
