package integrationtests

import (
	"strings"
	"testing"
)

func TestSocketBasic(t *testing.T) {
	result, _ := runScenarioResult(t, "socket-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_socket",
			MinCount:   1,
		},
		{
			Tracepoint: "enter_close",
			MinCount:   1,
		},
	})

	assertTracepointPathPrefix(t, result, "enter_socket", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_close", "socket:1:")
}

func TestSocketpairBasic(t *testing.T) {
	result, _ := runScenarioResult(t, "socketpair-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_socketpair",
			MinCount:   1,
		},
		{
			Tracepoint: "enter_close",
			MinCount:   2,
		},
	})

	assertTracepointPathPrefix(t, result, "enter_socketpair", "socket:1:")
	if got := totalTracepointPathCount(result, "enter_close", "socket:1:"); got < 2 {
		t.Fatalf("enter_close records with tracked socket descriptor prefix = %d, want >= 2", got)
	}
}

func assertTracepointPathPrefix(t *testing.T, result TestResult, tracepoint, wantPrefix string) {
	t.Helper()
	if got := countTracepointPathPrefix(result, tracepoint, wantPrefix); got == 0 {
		t.Fatalf("expected at least one %s record with path prefix %q", tracepoint, wantPrefix)
	}
}

func countTracepointPathPrefix(result TestResult, tracepoint, wantPrefix string) int {
	var count int
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), tracepoint) {
			continue
		}
		if strings.HasPrefix(rec.Path, wantPrefix) {
			count++
		}
	}
	return count
}

func totalTracepointPathCount(result TestResult, tracepoint, wantPrefix string) uint64 {
	var total uint64
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), tracepoint) {
			continue
		}
		if strings.HasPrefix(rec.Path, wantPrefix) {
			total += rec.Cnt.Count
		}
	}
	return total
}
