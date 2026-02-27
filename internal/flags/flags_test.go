package flags

import (
	"flag"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

func parseForTest(t *testing.T, args ...string) Flags {
	t.Helper()

	oldCommandLine := flag.CommandLine
	oldArgs := os.Args
	oldSingleton := singleton
	oldOnce := once
	oldPID := pidFilter.Load()
	oldTID := tidFilter.Load()
	oldTUIExport := tuiExportEnable.Load()

	fs := flag.NewFlagSet("ior-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flag.CommandLine = fs
	os.Args = append([]string{"ior"}, args...)

	singleton = Flags{TUIExportEnable: true}
	once = sync.Once{}
	pidFilter.Store(-1)
	tidFilter.Store(-1)
	tuiExportEnable.Store(true)

	parse()
	cfg := singleton

	t.Cleanup(func() {
		flag.CommandLine = oldCommandLine
		os.Args = oldArgs
		singleton = oldSingleton
		once = oldOnce
		pidFilter.Store(oldPID)
		tidFilter.Store(oldTID)
		tuiExportEnable.Store(oldTUIExport)
	})

	return cfg
}

func TestParseLiveFlagsAndInterval(t *testing.T) {
	cfg := parseForTest(t, "-live", "-live-interval", "200ms", "-pid", "1234")

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
}

func TestParseLiveDefaults(t *testing.T) {
	cfg := parseForTest(t)

	if cfg.LiveFlamegraph {
		t.Fatalf("expected live mode disabled by default")
	}
	if cfg.LiveInterval != time.Second {
		t.Fatalf("default live interval = %v, want %v", cfg.LiveInterval, time.Second)
	}
}
