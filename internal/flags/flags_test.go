package flags

import (
	"flag"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func parseForTest(t *testing.T, args ...string) (Flags, error) {
	t.Helper()

	oldCommandLine := flag.CommandLine
	oldArgs := os.Args
	oldSingleton := singleton
	oldOnce := once
	oldParseErr := parseErr
	oldPID := pidFilter.Load()
	oldTID := tidFilter.Load()
	oldTUIExport := tuiExportEnable.Load()

	fs := flag.NewFlagSet("ior-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flag.CommandLine = fs
	os.Args = append([]string{"ior"}, args...)

	singleton = Flags{TUIExportEnable: true}
	once = sync.Once{}
	parseErr = nil
	pidFilter.Store(-1)
	tidFilter.Store(-1)
	tuiExportEnable.Store(true)

	err := parse()
	cfg := singleton

	t.Cleanup(func() {
		flag.CommandLine = oldCommandLine
		os.Args = oldArgs
		singleton = oldSingleton
		once = oldOnce
		parseErr = oldParseErr
		pidFilter.Store(oldPID)
		tidFilter.Store(oldTID)
		tuiExportEnable.Store(oldTUIExport)
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
	if got := int(pidFilter.Load()); got != 1234 {
		t.Fatalf("global pid filter = %d, want 1234", got)
	}
	if cfg.OpenCommand != "" {
		t.Fatalf("expected empty open command by default")
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
