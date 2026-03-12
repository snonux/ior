package flags

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func parseForTest(t *testing.T, args ...string) (Config, error) {
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
	if got := Get().GetPidFilter(); got != 1234 {
		t.Fatalf("Get().GetPidFilter() = %d, want 1234", got)
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
