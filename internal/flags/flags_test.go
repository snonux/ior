package flags

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func parseForTest(t *testing.T, args ...string) (Flags, error) {
	t.Helper()

	oldCommandLine := flag.CommandLine
	oldArgs := os.Args
	oldCurrent := Get()
	oldParseErr := parseErr

	fs := flag.NewFlagSet("ior-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flag.CommandLine = fs
	os.Args = append([]string{"ior"}, args...)

	setCurrent(NewFlags())
	parseErr = nil

	err := parse()
	cfg := Get()

	t.Cleanup(func() {
		flag.CommandLine = oldCommandLine
		os.Args = oldArgs
		setCurrent(oldCurrent)
		parseErr = oldParseErr
	})

	return cfg, err
}

func TestParseLiveFlagsAndInterval(t *testing.T) {
	cfg, err := parseForTest(t, "-live", "-live-interval", "200ms", "-pid", "1234")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}

	if !cfg.LiveFlamegraph {
		t.Fatalf("expected -live to enable live mode")
	}
	if cfg.LiveInterval != 200*time.Millisecond {
		t.Fatalf("live interval = %v, want %v", cfg.LiveInterval, 200*time.Millisecond)
	}
	if cfg.PidFilter != 1234 {
		t.Fatalf("pid filter = %d, want 1234", cfg.PidFilter)
	}
	if got := Get().GetPidFilter(); got != 1234 {
		t.Fatalf("Get().GetPidFilter() = %d, want 1234", got)
	}
	if cfg.OpenCommand != "" {
		t.Fatalf("expected empty open command by default")
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

	if cfg.LiveFlamegraph {
		t.Fatalf("expected live mode disabled by default")
	}
	if cfg.LiveInterval != 200*time.Millisecond {
		t.Fatalf("default live interval = %v, want %v", cfg.LiveInterval, 200*time.Millisecond)
	}
	if cfg.OpenCommand != "" {
		t.Fatalf("expected empty open command by default")
	}
}

func TestParseOpenFlags(t *testing.T) {
	cfg, err := parseForTest(t, "-live", "-open", "chromium --new-window")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.LiveFlamegraph {
		t.Fatalf("expected live mode enabled")
	}
	if cfg.OpenCommand != "chromium --new-window" {
		t.Fatalf("open command = %q, want %q", cfg.OpenCommand, "chromium --new-window")
	}
}

func TestParseFlamegraphJSONFlag(t *testing.T) {
	cfg, err := parseForTest(t, "-flamegraphJson")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if !cfg.FlamegraphJSON {
		t.Fatalf("expected -flamegraphJson to enable JSON export")
	}
}

func TestParseIorWatchIntervalFlag(t *testing.T) {
	cfg, err := parseForTest(t, "-iorWatchInterval", "2s")
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if cfg.IorWatchInterval != 2*time.Second {
		t.Fatalf("ior watch interval = %v, want %v", cfg.IorWatchInterval, 2*time.Second)
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

func TestParseDefaultCollapsedFieldsOrder(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}

	want := []string{"comm", "path", "tracepoint"}
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
