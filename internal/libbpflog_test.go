package internal

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
)

// withLibbpfLogger points the process-wide libbpf logger at a buffer for one
// test and restores the production headless configuration afterwards, so the
// global callback never leaks a test buffer into later tests.
func withLibbpfLogger(t *testing.T, tui, verbose bool) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := libbpfLog.out
	libbpfLog.out = &buf
	libbpfLog.configure(tui, verbose)
	bpf.SetLoggerCbs(bpf.Callbacks{Log: libbpfLog.log})
	t.Cleanup(func() {
		libbpfLog.out = prev
		setLibbpfLogging(false)
	})
	return &buf
}

func TestLibbpfLoggerKeepsOnlyWarningsInHeadlessMode(t *testing.T) {
	buf := withLibbpfLogger(t, false, false)

	libbpfLog.log(bpf.LibbpfDebugLevel, "libbpf: debug line\n")
	libbpfLog.log(bpf.LibbpfInfoLevel, "libbpf: info line\n")
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: warn line\n")

	if got, want := buf.String(), "libbpf: warn line\n"; got != want {
		t.Fatalf("headless libbpf output = %q, want only %q", got, want)
	}
}

func TestLibbpfLoggerVerboseKeepsEveryLevelHeadless(t *testing.T) {
	buf := withLibbpfLogger(t, false, true)

	libbpfLog.log(bpf.LibbpfDebugLevel, "d\n")
	libbpfLog.log(bpf.LibbpfInfoLevel, "i\n")
	libbpfLog.log(bpf.LibbpfWarnLevel, "w\n")

	if got, want := buf.String(), "d\ni\nw\n"; got != want {
		t.Fatalf("verbose libbpf output = %q, want %q", got, want)
	}
}

// TestLibbpfLoggerVerboseIsIgnoredInTUIMode: stderr is the dashboard there, so
// the debug switch must not be able to write to it.
func TestLibbpfLoggerVerboseIsIgnoredInTUIMode(t *testing.T) {
	buf := withLibbpfLogger(t, true, true)

	libbpfLog.log(bpf.LibbpfDebugLevel, "d\n")
	libbpfLog.log(bpf.LibbpfWarnLevel, "w\n")

	if buf.Len() != 0 {
		t.Fatalf("TUI mode wrote %q to the headless output", buf.String())
	}
}

func TestLibbpfLoggerRoutesTUIWarningsToSetupSinkOnly(t *testing.T) {
	buf := withLibbpfLogger(t, true, false)
	warnings := &setupWarnings{}

	end := libbpfLog.routeWarnings(warnings.add)
	libbpfLog.log(bpf.LibbpfDebugLevel, "libbpf: debug line\n")
	libbpfLog.log(bpf.LibbpfInfoLevel, "libbpf: info line\n")
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: prog 'x': failed to attach\n")
	end()
	// After the setup window nothing may reach the collector or stderr.
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: late warning\n")

	got := warnings.drain()
	if len(got) != 1 || got[0] != "libbpf: prog 'x': failed to attach" {
		t.Fatalf("routed warnings = %q, want the single trimmed WARN line", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("TUI mode wrote %q to the headless output", buf.String())
	}
}

func TestLibbpfLoggerRouteWarningsIsNoOpHeadless(t *testing.T) {
	buf := withLibbpfLogger(t, false, false)
	warnings := &setupWarnings{}

	end := libbpfLog.routeWarnings(warnings.add)
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: warn line\n")
	end()

	if got := warnings.drain(); len(got) != 0 {
		t.Fatalf("headless warnings were diverted to the collector: %q", got)
	}
	if got, want := buf.String(), "libbpf: warn line\n"; got != want {
		t.Fatalf("headless output = %q, want %q (stderr stays the destination)", got, want)
	}
}

func TestLibbpfDebugRequested(t *testing.T) {
	for value, want := range map[string]bool{"": false, "0": false, "1": true, "true": true, "yes": true} {
		if got := libbpfDebugRequested(value); got != want {
			t.Errorf("libbpfDebugRequested(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestEmbeddedObjectOpenIsQuietByDefault runs real libbpf: opening the embedded
// BPF object makes it emit thousands of DEBUG lines, which the default policy
// must drop, while the verbose switch must let through (proving the callback
// really is the sink libbpf writes to). Opening needs no privileges; loading
// into the kernel is not attempted.
func TestEmbeddedObjectOpenIsQuietByDefault(t *testing.T) {
	open := func() {
		module, err := openBPFFileUnprivileged(filepath.Join("c", embeddedBPFObjectName))
		if err != nil {
			t.Fatalf("open embedded BPF object: %v", err)
		}
		module.Close()
	}

	quiet := withLibbpfLogger(t, false, false)
	open()
	if quiet.Len() != 0 {
		t.Fatalf("default policy let %d bytes of libbpf output through, first line: %q",
			quiet.Len(), firstLine(quiet.String()))
	}

	verbose := withLibbpfLogger(t, false, true)
	open()
	if !strings.Contains(verbose.String(), "libbpf:") {
		t.Fatalf("verbose mode captured no libbpf output (%d bytes): the callback is not libbpf's sink", verbose.Len())
	}
}

// TestNonBPFObjectWarningSurvivesFilter: a failure libbpf reports at WARN
// level - the reason a load fails - must still be visible in headless mode.
// The test binary is a valid ELF file that is not a BPF object, which libbpf
// rejects with an explanation.
func TestNonBPFObjectWarningSurvivesFilter(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	buf := withLibbpfLogger(t, false, false)

	if module, err := openBPFFileUnprivileged(self); err == nil {
		module.Close()
		t.Fatal("opening a non-BPF ELF file unexpectedly succeeded")
	}
	if !strings.Contains(buf.String(), "libbpf:") {
		t.Fatalf("libbpf's failure explanation was filtered away; output = %q", buf.String())
	}
}

// openBPFFileUnprivileged opens (parses, does not load) a BPF object file
// without the RLIMIT_MEMLOCK bump the plain constructor insists on, so these
// tests exercise real libbpf output without root. (The buffer constructor
// ignores SkipMemlockBump in this libbpfgo version, hence a file.)
func openBPFFileUnprivileged(path string) (*bpf.Module, error) {
	return bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath:      path,
		SkipMemlockBump: true,
	})
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
