package flags

import (
	"strings"
	"testing"

	"ior/internal/types"
)

func TestParseSamplingRates(t *testing.T) {
	cfg, err := parseForTest(t,
		"-syscall-sampling-families", "Time=100,misc=0",
		"-syscall-sampling-syscalls", "futex=0,clock_gettime=7",
	)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}

	if got := cfg.SyscallFamilySamplingRates[types.FamilyTime]; got != 100 {
		t.Fatalf("Time family rate = %d, want 100", got)
	}
	if got := cfg.SyscallFamilySamplingRates[types.FamilyMisc]; got != 0 {
		t.Fatalf("Misc family rate = %d, want 0", got)
	}
	if got := cfg.SyscallSamplingRates["futex"]; got != 0 {
		t.Fatalf("futex rate = %d, want 0", got)
	}
	if got := cfg.SyscallSamplingRates["clock_gettime"]; got != 7 {
		t.Fatalf("clock_gettime rate = %d, want 7", got)
	}
}

func TestParseSamplingFamilyRejectsUnknown(t *testing.T) {
	_, err := parseForTest(t, "-syscall-sampling-families", "Nope=4")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "invalid syscall family") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSamplingSyscallRejectsMalformedEntry(t *testing.T) {
	_, err := parseForTest(t, "-syscall-sampling-syscalls", "futex")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "expected name=rate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSamplingSyscallRejectsUnknownName(t *testing.T) {
	_, err := parseForTest(t, "-syscall-sampling-syscalls", "not_a_syscall=2")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "invalid syscall in sampling map") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCloneDeepCopiesSamplingMaps(t *testing.T) {
	cfg := NewFlags()
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 5
	cfg.SyscallSamplingRates["futex"] = 9

	cloned := cfg.Clone()
	cloned.SyscallFamilySamplingRates[types.FamilyTime] = 100
	cloned.SyscallSamplingRates["futex"] = 1

	if got := cfg.SyscallFamilySamplingRates[types.FamilyTime]; got != 5 {
		t.Fatalf("original family rate mutated: got %d, want 5", got)
	}
	if got := cfg.SyscallSamplingRates["futex"]; got != 9 {
		t.Fatalf("original syscall rate mutated: got %d, want 9", got)
	}
}

func TestDefaultSamplingRatesIncludeFutexAggregateOnly(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	for _, syscall := range []string{"futex", "futex_wait", "futex_wake", "futex_requeue", "futex_waitv", "clock_gettime"} {
		rate, ok := cfg.SyscallSamplingRates[syscall]
		if !ok {
			t.Fatalf("expected default sampling entry for %s", syscall)
		}
		if rate != 0 {
			t.Fatalf("%s default rate = %d, want 0 (aggregate-only)", syscall, rate)
		}
	}
}

func TestParseSamplingRatesOverrideDefaultFutexRate(t *testing.T) {
	cfg, err := parseForTest(t, "-syscall-sampling-syscalls", "futex=7")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if got := cfg.SyscallSamplingRates["futex"]; got != 7 {
		t.Fatalf("futex rate = %d, want 7", got)
	}
}

func TestPlainModePromotesAggregateOnlyDefaults(t *testing.T) {
	cfg, err := parseForTest(t, "-plain")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	for _, syscall := range []string{"futex", "futex_wait", "futex_wake", "futex_requeue", "futex_waitv", "clock_gettime"} {
		rate, ok := cfg.SyscallSamplingRates[syscall]
		if !ok {
			t.Fatalf("expected sampling entry for %s in plain mode", syscall)
		}
		if rate != 1 {
			t.Fatalf("%s rate in plain mode = %d, want 1 (promoted from aggregate-only)", syscall, rate)
		}
	}
}

func TestFlamegraphModePromotesAggregateOnlyDefaults(t *testing.T) {
	cfg, err := parseForTest(t, "-flamegraph")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if got := cfg.SyscallSamplingRates["clock_gettime"]; got != 1 {
		t.Fatalf("clock_gettime rate in flamegraph mode = %d, want 1", got)
	}
}

func TestParquetModePromotesAggregateOnlyDefaults(t *testing.T) {
	cfg, err := parseForTest(t, "-parquet", "trace.parquet")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if got := cfg.SyscallSamplingRates["futex"]; got != 1 {
		t.Fatalf("futex rate in parquet mode = %d, want 1", got)
	}
}

func TestPlainModePreservesExplicitAggregateOnly(t *testing.T) {
	cfg, err := parseForTest(t, "-plain", "-syscall-sampling-syscalls", "futex=0")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	// User explicitly requested aggregate-only for futex; it should stay 0.
	if got := cfg.SyscallSamplingRates["futex"]; got != 0 {
		t.Fatalf("futex rate = %d, want 0 (explicit override preserved)", got)
	}
	// clock_gettime was not overridden, so it should be promoted to 1.
	if got := cfg.SyscallSamplingRates["clock_gettime"]; got != 1 {
		t.Fatalf("clock_gettime rate = %d, want 1 (default promoted)", got)
	}
}

func TestTUIModeKeepsAggregateOnlyDefaults(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	// In TUI mode (no -plain, -flamegraph, or -parquet), defaults should
	// remain aggregate-only (rate 0) because the aggregate sink is present.
	for _, syscall := range []string{"futex", "clock_gettime"} {
		if got := cfg.SyscallSamplingRates[syscall]; got != 0 {
			t.Fatalf("%s rate in TUI mode = %d, want 0 (aggregate-only default)", syscall, got)
		}
	}
}

func TestIsRawOutputMode(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"default TUI", Config{}, false},
		{"plain", Config{PlainMode: true}, true},
		{"flamegraph", Config{FlamegraphOutput: true}, true},
		{"parquet", Config{ParquetPath: "trace.parquet"}, true},
		{"parquet whitespace", Config{ParquetPath: "  "}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.IsRawOutputMode(); got != tc.want {
				t.Fatalf("IsRawOutputMode() = %v, want %v", got, tc.want)
			}
		})
	}
}
