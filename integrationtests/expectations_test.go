package integrationtests

import (
	"ior/internal/flamegraph"
	"ior/internal/types"
	"testing"
)

func TestAssertEventsAbsentNoMatch(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "missing.txt"},
	})
	if mt.Failed() {
		t.Error("AssertEventsAbsent should not fail when event is absent")
	}
}

func TestAssertEventsAbsentWithMatch(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "testfile.txt"},
	})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should fail when event is present")
	}
}

func TestAssertEventsAbsentEmptyResult(t *testing.T) {
	result := TestResult{}

	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "anything.txt"},
	})
	if mt.Failed() {
		t.Error("AssertEventsAbsent should not fail on empty result")
	}
}

func TestAssertEventsAbsentMultiField(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_WRITE, Comm: "ioworkload"},
		},
	}

	// Multi-field match: path + tracepoint + comm — all match first record.
	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "testfile.txt", Tracepoint: "enter_openat", Comm: "ioworkload"},
	})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should fail when multi-field event matches")
	}

	// Multi-field partial mismatch: path matches but tracepoint doesn't.
	mt2 := &testing.T{}
	AssertEventsAbsent(mt2, result, []ExpectedEvent{
		{PathContains: "testfile.txt", Tracepoint: "enter_read"},
	})
	if mt2.Failed() {
		t.Error("AssertEventsAbsent should pass when multi-field expectation partially mismatches")
	}
}

func TestAssertEventsAbsentMultipleExpectations(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/found.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	// First expectation absent, second present — should fail.
	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "missing.txt"},
		{PathContains: "found.txt"},
	})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should fail when any expectation matches")
	}
}

func TestAssertEventsAbsentRejectsZeroValue(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	// Zero-value ExpectedEvent should be rejected with an error.
	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{{}})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should reject zero-value ExpectedEvent")
	}
}
