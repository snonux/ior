package flags

import (
	"flag"
	"io"
	"strings"
	"testing"
	"time"
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

func TestParseTUIFastRefreshZeroDisables(t *testing.T) {
	// A zero value is valid and means "disable high-frequency refresh",
	// falling back to the default Bubble Tea tick rate.
	cfg, err := parseForTest(t, "-tui-fast-refresh", "0")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.TUIFastRefreshInterval != 0 {
		t.Fatalf("TUIFastRefreshInterval = %v, want 0 (disabled)", cfg.TUIFastRefreshInterval)
	}
}
