package flags

import (
	"flag"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"ior/internal/collapse"
	"ior/internal/textsafe"
)

// parseForTest builds a fresh FlagSet and parses the given args, returning
// the resulting Config. It avoids touching any global state so tests can run
// in parallel without interfering with each other.
func parseForTest(t *testing.T, args ...string) (Config, error) {
	t.Helper()
	fs := flag.NewFlagSet("ior-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return parseFromFlagSet(fs, args)
}

func TestParseLiveIntervalAndPID(t *testing.T) {
	cfg, err := parseForTest(t, "-live-interval", "200ms", "-pid", "1234")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}

	if cfg.LiveInterval != 200*time.Millisecond {
		t.Fatalf("live interval = %v, want %v", cfg.LiveInterval, 200*time.Millisecond)
	}
	if cfg.PidFilter != 1234 {
		t.Fatalf("pid filter = %d, want 1234", cfg.PidFilter)
	}
	if got := cfg.GetPidFilter(); got != 1234 {
		t.Fatalf("cfg.GetPidFilter() = %d, want 1234", got)
	}
}

func TestNewFlagsDefaultsAndGetters(t *testing.T) {
	cfg := NewFlags()
	if cfg.GetPidFilter() != -1 {
		t.Fatalf("GetPidFilter() = %d, want -1", cfg.GetPidFilter())
	}
	if cfg.GetTidFilter() != -1 {
		t.Fatalf("GetTidFilter() = %d, want -1", cfg.GetTidFilter())
	}
	if !cfg.GetTUIExportEnable() {
		t.Fatalf("GetTUIExportEnable() = false, want true")
	}
	if cfg.CountField != "count" {
		t.Fatalf("CountField = %q, want count", cfg.CountField)
	}
}

func TestParseLiveDefaults(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}

	if cfg.LiveInterval != 200*time.Millisecond {
		t.Fatalf("default live interval = %v, want %v", cfg.LiveInterval, 200*time.Millisecond)
	}
}

func TestParseTestFlamesFlag(t *testing.T) {
	cfg, err := parseForTest(t, "--testflames")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.TestFlames {
		t.Fatalf("expected --testflames to enable static flamegraph test mode")
	}
}

func TestParseTestLiveFlamesFlag(t *testing.T) {
	cfg, err := parseForTest(t, "--testliveflames")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.TestLiveFlames {
		t.Fatalf("expected --testliveflames to enable synthetic live flamegraph test mode")
	}
}

func TestParseFlamegraphOutputFlags(t *testing.T) {
	cfg, err := parseForTest(t, "--flamegraph", "--name", "scenario-run")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.FlamegraphOutput {
		t.Fatalf("expected --flamegraph to enable .ior.zst output mode")
	}
	if got, want := cfg.OutputName, "scenario-run"; got != want {
		t.Fatalf("output name = %q, want %q", got, want)
	}
}

func TestParseParquetOutputFlag(t *testing.T) {
	cfg, err := parseForTest(t, "--parquet", "trace-run")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if got, want := cfg.ParquetPath, "trace-run"; got != want {
		t.Fatalf("parquet path = %q, want %q", got, want)
	}
}

func TestParseDefaultCollapsedFieldsOrder(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}

	want := []string{"comm", "tracepoint", "path"}
	if len(cfg.CollapsedFields) != len(want) {
		t.Fatalf("default collapsed fields len = %d, want %d", len(cfg.CollapsedFields), len(want))
	}
	for i := range want {
		if cfg.CollapsedFields[i] != want[i] {
			t.Fatalf("default collapsed fields[%d] = %q, want %q", i, cfg.CollapsedFields[i], want[i])
		}
	}
}

func TestParseInvalidCollapsedFieldReturnsError(t *testing.T) {
	_, err := parseForTest(t, "-fields", "comm,invalid")
	if err == nil {
		t.Fatalf("expected parse error for invalid collapsed field")
	}
	if !strings.Contains(err.Error(), "invalid field for collapse: invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseInvalidCountFieldReturnsError(t *testing.T) {
	_, err := parseForTest(t, "-count", "invalid")
	if err == nil {
		t.Fatalf("expected parse error for invalid count field")
	}
	if !strings.Contains(err.Error(), "invalid count field: invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseInvalidTracepointRegexReturnsError(t *testing.T) {
	_, err := parseForTest(t, "-tps", "[")
	if err == nil {
		t.Fatalf("expected parse error for invalid tracepoint regex")
	}
	if !strings.Contains(err.Error(), "unable to compile regex") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestParseTracepointRegexListsTolerateBlankAndPaddedEntries checks the -tps
// and -tpsExclude flags end to end: a trailing comma must not turn into an
// empty regex that matches (and so attaches or excludes) every tracepoint, and
// a space after a comma must not produce a pattern that never matches.
func TestParseTracepointRegexListsTolerateBlankAndPaddedEntries(t *testing.T) {
	cfg, err := parseForTest(t,
		"-tps", "^sys_enter_openat$, ^sys_enter_read$, ^sys_enter_close$,",
		"-tpsExclude", "^sys_enter_close$,")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	sel := cfg.TracepointSelector
	for _, name := range []string{"sys_enter_openat", "sys_enter_read"} {
		if !sel.ShouldAttach(name) {
			t.Errorf("ShouldAttach(%q) = false, want true", name)
		}
	}
	// sys_enter_close is attached by -tps but must still be excluded;
	// sys_enter_write is outside the -tps list and must not be attached.
	for _, name := range []string{"sys_enter_close", "sys_enter_write"} {
		if sel.ShouldAttach(name) {
			t.Errorf("ShouldAttach(%q) = true, want false", name)
		}
	}
}

// TestParseBlankTpsBehavesLikeUnset drives a blank or comma-only -tps through
// the real flag parser: it must keep the FS-only default exactly as if the
// flag had not been given, rather than attaching every tracepoint.
func TestParseBlankTpsBehavesLikeUnset(t *testing.T) {
	for _, tps := range []string{" , ", ",", "   "} {
		t.Run(fmt.Sprintf("%q", tps), func(t *testing.T) {
			cfg, err := parseForTest(t, "-tps", tps)
			if err != nil {
				t.Fatalf("parse returned error: %v", err)
			}
			sel := cfg.TracepointSelector
			if !sel.RestrictSyscalls {
				t.Fatal("RestrictSyscalls = false, want FS-only default as with no -tps")
			}
			if !sel.ShouldAttach("sys_enter_openat") {
				t.Error("ShouldAttach(sys_enter_openat) = false, want true")
			}
			if sel.ShouldAttach("sys_enter_socket") {
				t.Error("ShouldAttach(sys_enter_socket) = true, want false as with no -tps")
			}
		})
	}
}

// TestParseBlankTpsExcludeWithTraceDimensions checks that a blank -tpsExclude
// excludes nothing when combined with -trace-* selectors (a stray empty regex
// would otherwise exclude every tracepoint).
func TestParseBlankTpsExcludeWithTraceDimensions(t *testing.T) {
	for _, exclude := range []string{" , ", ",", "   "} {
		t.Run(fmt.Sprintf("%q", exclude), func(t *testing.T) {
			cfg, err := parseForTest(t, "-trace-syscalls", "socket, openat", "-tpsExclude", exclude)
			if err != nil {
				t.Fatalf("parse returned error: %v", err)
			}
			sel := cfg.TracepointSelector
			if len(sel.Exclude) != 0 {
				t.Fatalf("len(Exclude) = %d, want 0", len(sel.Exclude))
			}
			for _, name := range []string{"sys_enter_socket", "sys_exit_openat"} {
				if !sel.ShouldAttach(name) {
					t.Errorf("ShouldAttach(%q) = false, want true", name)
				}
			}
			if sel.ShouldAttach("sys_enter_read") {
				t.Error("ShouldAttach(sys_enter_read) = true, want false (not in -trace-syscalls)")
			}
		})
	}
}

// TestParseFieldsTrimsAndSkipsBlankEntries pins -fields splitting: padding
// around entries is ignored, stray commas are dropped, and a blank or
// comma-only value falls back to the default field list.
func TestParseFieldsTrimsAndSkipsBlankEntries(t *testing.T) {
	tests := []struct {
		name   string
		fields string
		want   []string
	}{
		{name: "padded entries", fields: " path , comm ", want: []string{"path", "comm"}},
		{name: "stray commas", fields: ",comm,,pid,", want: []string{"comm", "pid"}},
		{name: "comma only uses defaults", fields: " , ", want: collapse.DefaultFields()},
		{name: "blank uses defaults", fields: "  ", want: collapse.DefaultFields()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseForTest(t, "-fields", tt.fields)
			if err != nil {
				t.Fatalf("parse returned error: %v", err)
			}
			if !slices.Equal(cfg.CollapsedFields, tt.want) {
				t.Fatalf("CollapsedFields = %q, want %q", cfg.CollapsedFields, tt.want)
			}
		})
	}
}

func TestParseFieldsInvalidEntryAmongPaddedEntriesReturnsError(t *testing.T) {
	_, err := parseForTest(t, "-fields", " comm , bogus ,")
	if err == nil {
		t.Fatal("expected parse error for invalid collapse field")
	}
	if !strings.Contains(err.Error(), "invalid field for collapse: bogus") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDefaultTraceDimensionsFSOnly(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.TracepointSelector.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat attached by default")
	}
	if cfg.TracepointSelector.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep excluded by default")
	}
}

func TestParseTraceFamiliesFlag(t *testing.T) {
	cfg, err := parseForTest(t, "-trace-families", "Time")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.TracepointSelector.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep attached for Time family")
	}
	if cfg.TracepointSelector.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat excluded when only Time family enabled")
	}
}

func TestParseTraceKindsFlag(t *testing.T) {
	cfg, err := parseForTest(t, "-trace-kinds", "sleep")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.TracepointSelector.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep attached for sleep kind")
	}
	if cfg.TracepointSelector.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat excluded for sleep-only selector")
	}
}

func TestParseTraceSyscallsFlag(t *testing.T) {
	cfg, err := parseForTest(t, "-trace-syscalls", "openat")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.TracepointSelector.ShouldAttach("sys_enter_openat") || !cfg.TracepointSelector.ShouldAttach("sys_exit_openat") {
		t.Fatal("expected openat enter/exit attached")
	}
	if cfg.TracepointSelector.ShouldAttach("sys_enter_write") {
		t.Fatal("expected write excluded when only openat enabled")
	}
}

func TestParseTraceDimensionsUnionAndExclusions(t *testing.T) {
	cfg, err := parseForTest(t,
		"-trace-families", "Time",
		"-trace-syscalls", "openat",
		"-no-trace-syscalls", "openat",
	)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.TracepointSelector.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat excluded by no-trace-syscalls")
	}
	if !cfg.TracepointSelector.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep still attached from trace-families")
	}
}

func TestParseTraceFamiliesRejectsUnknown(t *testing.T) {
	_, err := parseForTest(t, "-trace-families", "Nope")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "invalid syscall family") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseTraceKindsRejectsUnknown(t *testing.T) {
	_, err := parseForTest(t, "-trace-kinds", "not-a-kind")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "invalid syscall kind") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseTraceSyscallsRejectsUnknown(t *testing.T) {
	_, err := parseForTest(t, "-trace-syscalls", "definitely_not_syscall")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "invalid syscall in trace selector") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseResetTimerDefault(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.ResetTimer != DefaultResetTimer {
		t.Fatalf("default reset timer = %v, want %v", cfg.ResetTimer, DefaultResetTimer)
	}
}

func TestParseResetTimerOverride(t *testing.T) {
	cfg, err := parseForTest(t, "-resetTimer", "45s")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.ResetTimer != 45*time.Second {
		t.Fatalf("reset timer = %v, want 45s", cfg.ResetTimer)
	}
}

func TestParseResetTimerZeroDisables(t *testing.T) {
	cfg, err := parseForTest(t, "-resetTimer", "0")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.ResetTimer != 0 {
		t.Fatalf("reset timer = %v, want 0 (disabled)", cfg.ResetTimer)
	}
}

func TestParseResetTimerNegativeReturnsError(t *testing.T) {
	_, err := parseForTest(t, "-resetTimer", "-5s")
	if err == nil {
		t.Fatalf("expected parse error for negative reset timer")
	}
	if !strings.Contains(err.Error(), "invalid resetTimer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDurationNegativeReturnsError(t *testing.T) {
	_, err := parseForTest(t, "-duration", "-1")
	if err == nil {
		t.Fatalf("expected parse error for negative duration")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDurationZeroReturnsError(t *testing.T) {
	_, err := parseForTest(t, "-duration", "0")
	if err == nil {
		t.Fatalf("expected parse error for zero duration")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestParseDurationOverflowReturnsError guards against -duration values whose
// seconds-to-time.Duration conversion overflows int64 into a negative timeout,
// which used to end the trace immediately with exit 0.
func TestParseDurationOverflowReturnsError(t *testing.T) {
	for _, value := range []string{
		"10000000000", // the reported repro
		strconv.FormatInt(maxDurationSeconds+1, 10), // first overflowing value
		strconv.FormatInt(math.MaxInt64, 10),        // extreme
	} {
		_, err := parseForTest(t, "-duration", value)
		if err == nil {
			t.Fatalf("-duration %s: expected parse error for overflowing duration", value)
		}
		if !strings.Contains(err.Error(), "invalid duration") {
			t.Fatalf("-duration %s: unexpected error: %v", value, err)
		}
	}
}

// TestParseDurationMaxAccepted pins the boundary: the largest duration that
// still fits in a time.Duration must be accepted and convert to a positive
// timeout.
func TestParseDurationMaxAccepted(t *testing.T) {
	cfg, err := parseForTest(t, "-duration", strconv.FormatInt(maxDurationSeconds, 10))
	if err != nil {
		t.Fatalf("parse returned unexpected error: %v", err)
	}
	if got := time.Duration(cfg.Duration) * time.Second; got <= 0 {
		t.Fatalf("max duration converted to non-positive timeout %v", got)
	}
}

func TestParseDurationPositiveAccepted(t *testing.T) {
	cfg, err := parseForTest(t, "-duration", "60")
	if err != nil {
		t.Fatalf("parse returned unexpected error: %v", err)
	}
	if cfg.Duration != 60 {
		t.Fatalf("duration = %d, want 60", cfg.Duration)
	}
}

func TestParseNegativeMapSizeReturnsError(t *testing.T) {
	// A negative mapSize wraps to a huge uint32 when cast in resizeBPFMaps,
	// causing a confusing BPF load failure. Parse must catch it early.
	_, err := parseForTest(t, "-mapSize", "-1")
	if err == nil {
		t.Fatalf("expected parse error for negative mapSize")
	}
	if !strings.Contains(err.Error(), "invalid mapSize") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseZeroMapSizeReturnsError(t *testing.T) {
	// A zero mapSize would allocate an empty BPF ring buffer, which is
	// equally invalid. Parse must catch it early.
	_, err := parseForTest(t, "-mapSize", "0")
	if err == nil {
		t.Fatalf("expected parse error for zero mapSize")
	}
	if !strings.Contains(err.Error(), "invalid mapSize") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePositiveMapSizeAccepted(t *testing.T) {
	cfg, err := parseForTest(t, "-mapSize", "8192")
	if err != nil {
		t.Fatalf("parse returned unexpected error: %v", err)
	}
	if cfg.EventMapSize != 8192 {
		t.Fatalf("EventMapSize = %d, want 8192", cfg.EventMapSize)
	}
}

func TestParseTUIFastRefreshDefault(t *testing.T) {
	// Default should be 250ms — the high-frequency refresh cadence used by
	// the flamegraph and stream tabs when no explicit flag is provided.
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.TUIFastRefreshInterval != 250*time.Millisecond {
		t.Fatalf("default TUIFastRefreshInterval = %v, want 250ms", cfg.TUIFastRefreshInterval)
	}
}

func TestParseTUIFastRefreshOverride(t *testing.T) {
	// An explicit -tui-fast-refresh value must be respected and stored on cfg.
	cfg, err := parseForTest(t, "-tui-fast-refresh", "100ms")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.TUIFastRefreshInterval != 100*time.Millisecond {
		t.Fatalf("TUIFastRefreshInterval = %v, want 100ms", cfg.TUIFastRefreshInterval)
	}
}

func TestParseTUIFastRefreshZeroFallsBackToBuiltinTick(t *testing.T) {
	// A zero value is valid: it clears the configured override so the
	// dashboard falls back to its built-in 200ms flame/stream tick
	// constants. High-frequency refresh is never fully disabled.
	cfg, err := parseForTest(t, "-tui-fast-refresh", "0")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.TUIFastRefreshInterval != 0 {
		t.Fatalf("TUIFastRefreshInterval = %v, want 0 (built-in tick fallback)", cfg.TUIFastRefreshInterval)
	}
}

// TestParseEscapeMode checks -escape defaults to auto, accepts each mode and
// rejects an invalid value at parse time instead of silently falling back.
func TestParseEscapeMode(t *testing.T) {
	cfg, err := parseForTest(t, "-plain")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.EscapeMode != textsafe.EscapeAuto {
		t.Fatalf("default EscapeMode = %q, want auto", cfg.EscapeMode)
	}
	for _, mode := range []textsafe.EscapeMode{textsafe.EscapeAuto, textsafe.EscapeAlways, textsafe.EscapeNever} {
		cfg, err := parseForTest(t, "-plain", "-escape", string(mode))
		if err != nil {
			t.Fatalf("-escape %s returned error: %v", mode, err)
		}
		if cfg.EscapeMode != mode {
			t.Fatalf("-escape %s parsed as %q", mode, cfg.EscapeMode)
		}
	}
	for _, bad := range []string{"", "ALWAYS", "tty"} {
		if _, err := parseForTest(t, "-plain", "-escape="+bad); err == nil {
			t.Fatalf("-escape=%q succeeded, want an error", bad)
		}
	}
}
