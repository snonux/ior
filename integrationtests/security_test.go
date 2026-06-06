package integrationtests

import (
	"strings"
	"testing"
)

var securityTraceArgs = []string{"-trace-syscalls", "keyctl,add_key,request_key,ptrace,perf_event_open,close"}

func TestSecurityKeysPtracePerf(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "security-keys-ptrace-perf", []ExpectedEvent{
		{Tracepoint: "enter_keyctl", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_add_key", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_request_key", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_ptrace", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_perf_event_open", Comm: "ioworkload", MinCount: 1},
	}, securityTraceArgs)

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

var getrandomTraceArgs = []string{"-trace-syscalls", "getrandom"}

// TestSecurityGetrandom asserts end-to-end tracing of the getrandom syscall
// (Security family, READ_CLASSIFIED). The security-getrandom scenario fills a
// 32-byte buffer via unix.Getrandom, looping until the full buffer is filled.
//
// getrandom reports the number of random bytes written into buf as its return
// value, which ior records as the exit byte count. The scenario loops past any
// signal-interrupted short reads, so the cumulative byte count is strictly
// positive; we assert bytes>=1 (the per-call count can be split across reads,
// so a conservative >=1 minimum is the safe invariant) plus a positive
// duration. The enter tracepoint is null-kind (no fd/path dimension), so only
// the READ byte-count classification is locked in here.
func TestSecurityGetrandom(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "security-getrandom", []ExpectedEvent{
		{Tracepoint: "enter_getrandom", Comm: "ioworkload", MinCount: 1},
	}, getrandomTraceArgs)

	exp := ExpectedEvent{Tracepoint: "enter_getrandom", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, exp, 1)
	assertEventDurationPositive(t, result, exp)
}

var landlockTraceArgs = []string{"-trace-syscalls", "landlock_create_ruleset,landlock_add_rule,close"}

// TestSecurityLandlockCreateRuleset asserts end-to-end tracing of the
// Security-family landlock_create_ruleset and landlock_add_rule syscalls. The
// security-landlock scenario calls landlock_create_ruleset(&attr, sizeof(attr),
// 0), adds a PATH_BENEATH rule via landlock_add_rule(ruleset_fd, rule_type,
// &attr, 0), and closes the returned ruleset fd (it deliberately never calls
// landlock_restrict_self, which would irreversibly sandbox the shared test
// runner).
//
// The sys_enter tracepoints fire before any ENOSYS/EOPNOTSUPP error, so both
// enter events are observed regardless of whether Landlock is enabled on the
// running kernel; we therefore assert the enter MinCounts unconditionally.
// landlock_create_ruleset is KindEventfd (it captures flags at args[2]); when
// the ruleset fd is successfully created and registered, it resolves to the
// "landlockfd:" path label, which is also seen on the matching close.
// landlock_add_rule captures ruleset_fd (KindFd) at args[0]; its return value
// (0 or -1) is UNCLASSIFIED, not a byte count.
func TestSecurityLandlockCreateRuleset(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "security-landlock", []ExpectedEvent{
		{Tracepoint: "enter_landlock_create_ruleset", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_landlock_add_rule", Comm: "ioworkload", MinCount: 1},
	}, landlockTraceArgs)

	for _, tracepoint := range []string{
		"enter_landlock_create_ruleset",
		"enter_landlock_add_rule",
	} {
		assertEventDurationPositive(t, result, ExpectedEvent{
			Tracepoint: tracepoint,
			Comm:       "ioworkload",
		})
	}

	// landlock_create_ruleset may fail (ENOSYS on kernels < 5.13, or
	// EOPNOTSUPP when the Landlock LSM is disabled). If a tracked ruleset fd
	// appears, it must carry the "landlockfd:" label and be closed under the
	// same label; otherwise we must observe no tracked landlock close events.
	landlockOpenTracked := totalTracepointPathCount(result, "enter_landlock_create_ruleset", "landlockfd:")
	landlockCloseTracked := totalTracepointPathCount(result, "enter_close", "landlockfd:")
	if landlockOpenTracked == 0 {
		if landlockCloseTracked != 0 {
			t.Fatalf("unexpected tracked landlock close events without tracked ruleset open: close=%d", landlockCloseTracked)
		}
		return
	}

	assertTracepointPathPrefix(t, result, "enter_landlock_create_ruleset", "landlockfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "landlockfd:")
	if landlockCloseTracked < landlockOpenTracked {
		t.Fatalf("tracked landlock close count too small: close=%d open=%d", landlockCloseTracked, landlockOpenTracked)
	}

	// The tracked ruleset descriptor path should be stable between the
	// create_ruleset record and its matching close record.
	openPaths := uniqueTracepointPathsWithPrefix(result, "enter_landlock_create_ruleset", "landlockfd:")
	closePaths := uniqueTracepointPathsWithPrefix(result, "enter_close", "landlockfd:")
	for path := range openPaths {
		if _, ok := closePaths[path]; !ok {
			t.Fatalf("tracked landlock descriptor %q seen on create but not close", path)
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
