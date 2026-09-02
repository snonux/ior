package flags

import (
	"strconv"
	"strings"
	"testing"
)

// withPinnedPidMax pins the pid_max validation bound for one test so
// acceptance/rejection does not depend on the host's /proc/sys/kernel/pid_max.
func withPinnedPidMax(t *testing.T, max int) {
	t.Helper()
	previous := pidMaxFn
	pidMaxFn = func() int { return max }
	t.Cleanup(func() { pidMaxFn = previous })
}

// TestParseRejectsInvalidPIDAndTIDValues locks the startup validation for
// audit domain-06 F1: -pid/-tid values outside {-1} ∪ [1, pid_max] used to
// wrap to huge uint32 BPF globals and silently empty the trace.
func TestParseRejectsInvalidPIDAndTIDValues(t *testing.T) {
	withPinnedPidMax(t, fallbackPidMax)

	cases := []struct {
		name    string
		flag    string
		value   string
		wantErr string
	}{
		{"pid zero matches only the idle task", "pid", "0", "invalid pid: 0"},
		{"pid negative wraps to a huge uint32", "pid", "-2", "invalid pid: -2"},
		{"pid beyond pid_max cannot exist", "pid", "999999999", "invalid pid: 999999999"},
		{"tid zero matches only the idle task", "tid", "0", "invalid tid: 0"},
		{"tid negative wraps to a huge uint32", "tid", "-2", "invalid tid: -2"},
		{"tid beyond pid_max cannot exist", "tid", "999999999", "invalid tid: 999999999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseForTest(t, "-"+tc.flag, tc.value)
			if err == nil {
				t.Fatalf("parse accepted -%s %s, want rejection", tc.flag, tc.value)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parse error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestParseAcceptsValidPIDAndTIDValues locks the accepted range: the -1 "no
// filter" sentinel, the smallest real ID, and the pid_max boundary itself.
func TestParseAcceptsValidPIDAndTIDValues(t *testing.T) {
	withPinnedPidMax(t, fallbackPidMax)

	for _, flag := range []string{"pid", "tid"} {
		for _, value := range []string{"-1", "1", "4194304"} {
			t.Run(flag+" "+value, func(t *testing.T) {
				cfg, err := parseForTest(t, "-"+flag, value)
				if err != nil {
					t.Fatalf("parse rejected -%s %s: %v", flag, value, err)
				}
				got := cfg.PidFilter
				if flag == "tid" {
					got = cfg.TidFilter
				}
				want, err := strconv.Atoi(value)
				if err != nil {
					t.Fatalf("bad test value %q: %v", value, err)
				}
				if got != want {
					t.Fatalf("-%s = %d, want %d", flag, got, want)
				}
			})
		}
	}
}

// TestValidateProcessIDUsesDynamicPidMax proves the bound follows the host's
// pid_max (or its fallback) rather than a hardcoded constant.
func TestValidateProcessIDUsesDynamicPidMax(t *testing.T) {
	withPinnedPidMax(t, 32768)

	if err := validateProcessID("pid", 32768); err != nil {
		t.Fatalf("pid_max boundary rejected: %v", err)
	}
	if err := validateProcessID("pid", 32769); err == nil {
		t.Fatalf("value beyond the pinned pid_max accepted, want rejection")
	}
}
