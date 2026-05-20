package integrationtests

import (
	"strings"
	"testing"
)

func TestSecurityKeysPtracePerf(t *testing.T) {
	result, _ := runScenarioResult(t, "security-keys-ptrace-perf", []ExpectedEvent{
		{Tracepoint: "enter_keyctl", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_add_key", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_request_key", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_ptrace", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_perf_event_open", Comm: "ioworkload", MinCount: 1},
	})

	// Key and ptrace operations are not fd/path based and should stay untracked.
	assertTracepointPathPrefix(t, result, "enter_keyctl", "N:file")
	assertTracepointPathPrefix(t, result, "enter_add_key", "N:file")
	assertTracepointPathPrefix(t, result, "enter_request_key", "N:file")
	assertTracepointPathPrefix(t, result, "enter_ptrace", "N:file")

	for _, tracepoint := range []string{
		"enter_keyctl",
		"enter_add_key",
		"enter_request_key",
		"enter_ptrace",
		"enter_perf_event_open",
	} {
		assertEventDurationPositive(t, result, ExpectedEvent{
			Tracepoint: tracepoint,
			Comm:       "ioworkload",
		})
	}

	// perf_event_open may fail (e.g. EPERM), so assert conditional behavior:
	// if a tracked perf descriptor appears, we must also observe a close on it.
	perfOpenTracked := totalTracepointPathCount(result, "enter_perf_event_open", "perf:")
	perfCloseTracked := totalTracepointPathCount(result, "enter_close", "perf:")
	if perfOpenTracked == 0 {
		if perfCloseTracked != 0 {
			t.Fatalf("unexpected tracked perf close events without tracked perf open: close=%d", perfCloseTracked)
		}
		return
	}

	assertTracepointPathPrefix(t, result, "enter_perf_event_open", "perf:")
	assertTracepointPathPrefix(t, result, "enter_close", "perf:")
	if perfCloseTracked < perfOpenTracked {
		t.Fatalf("tracked perf close count too small: close=%d open=%d", perfCloseTracked, perfOpenTracked)
	}

	// Tracked perf descriptor path should be stable between open and close records.
	openPaths := uniqueTracepointPathsWithPrefix(result, "enter_perf_event_open", "perf:")
	closePaths := uniqueTracepointPathsWithPrefix(result, "enter_close", "perf:")
	for path := range openPaths {
		if _, ok := closePaths[path]; !ok {
			t.Fatalf("tracked perf descriptor %q seen on open but not close", path)
		}
	}
}

func uniqueTracepointPathsWithPrefix(result TestResult, tracepoint, wantPrefix string) map[string]struct{} {
	paths := make(map[string]struct{})
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), tracepoint) {
			continue
		}
		if !strings.HasPrefix(rec.Path, wantPrefix) {
			continue
		}
		paths[rec.Path] = struct{}{}
	}
	return paths
}
