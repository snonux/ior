package internal

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
)

// withLibbpfLogger points the process-wide libbpf logger at a buffer for one
// test and restores the production headless configuration afterwards, so the
// global callback never leaks a test buffer into later tests.
func withLibbpfLogger(t *testing.T, tui, verbose bool) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	// out is read by log under mu (possibly from a libbpf thread), so it is
	// swapped under mu too. The libbpf callback itself is installed once in
	// init; re-installing it here would be the unsynchronised write to
	// libbpfgo's callbacks variable that production code avoids.
	setOut := func(w io.Writer) io.Writer {
		libbpfLog.mu.Lock()
		defer libbpfLog.mu.Unlock()
		prev := libbpfLog.out
		libbpfLog.out = w
		return prev
	}
	prev := setOut(&buf)
	libbpfLog.configure(tui, verbose)
	t.Cleanup(func() {
		setOut(prev)
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
	cases := map[string]bool{
		"": false, "0": false, "false": false, "no": false, "off": false,
		"False": false, "NO": false, "Off": false, " off ": false,
		"1": true, "true": true, "yes": true, "on": true, "debug": true,
	}
	for value, want := range cases {
		if got := libbpfDebugRequested(value); got != want {
			t.Errorf("libbpfDebugRequested(%q) = %v, want %v", value, got, want)
		}
	}
}

// overlappingSessions returns a TUI logger with session A (routed to a) and,
// started while A is still loading, session B (routed to b), the way a TUI
// restart overlaps the cancelled session's setup.
func overlappingSessions(t *testing.T) (a, b *setupWarnings, endA, endB func()) {
	t.Helper()
	withLibbpfLogger(t, true, false)
	a, b = &setupWarnings{}, &setupWarnings{}
	endA = libbpfLog.routeWarnings(a.add)
	// startTUITrace(B) switches the mode again before B's setup routes.
	setLibbpfLogging(true)
	endB = libbpfLog.routeWarnings(b.add)
	return a, b, endA, endB
}

// TestOverlappingSessionEndKeepsTheNewerRouting: A's deferred end must not
// clear B's route (it used to set the shared sink to nil), or the WARNs that
// explain why B's load failed vanish for the rest of B's setup.
func TestOverlappingSessionEndKeepsTheNewerRouting(t *testing.T) {
	a, b, endA, endB := overlappingSessions(t)

	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: during overlap\n")
	endA()
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: after A ended\n")
	endB()

	if got, want := b.drain(), []string{"libbpf: during overlap", "libbpf: after A ended"}; !slices.Equal(got, want) {
		t.Fatalf("session B received %q, want %q", got, want)
	}
	if got := a.drain(); len(got) != 0 {
		t.Fatalf("session A's collector received %q although B's route was the newest", got)
	}
}

// TestEndedSessionNeverReceivesLaterWarnings: once a session's end returned,
// its collector is never called again, whatever the other session does; in
// particular lines logged after both ended reach nobody.
func TestEndedSessionNeverReceivesLaterWarnings(t *testing.T) {
	a, b, endA, endB := overlappingSessions(t)

	endA()
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: late line\n")
	endB()
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: after everything\n")

	if got := a.drain(); len(got) != 0 {
		t.Fatalf("ended session A received %q", got)
	}
	if got, want := b.drain(), []string{"libbpf: late line"}; !slices.Equal(got, want) {
		t.Fatalf("session B received %q, want %q", got, want)
	}
}

// TestModeSwitchKeepsTheRunningSessionsRoute: startTUITrace calls
// setLibbpfLogging(true) for every trace start; it must not reset a route that
// an earlier, still loading session installed.
func TestModeSwitchKeepsTheRunningSessionsRoute(t *testing.T) {
	withLibbpfLogger(t, true, false)
	a := &setupWarnings{}
	end := libbpfLog.routeWarnings(a.add)
	defer end()

	setLibbpfLogging(true)
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: still routed\n")

	if got, want := a.drain(), []string{"libbpf: still routed"}; !slices.Equal(got, want) {
		t.Fatalf("routed warnings = %q, want %q", got, want)
	}
}

// TestOverlappingSessionsShareTheCollectorSafely is the -race test: session B's
// own setup code adds warnings (bpfSetupLog.warn) while libbpf output of the
// overlapping session A is routed into the same collector from another
// goroutine. Every message must arrive exactly once.
func TestOverlappingSessionsShareTheCollectorSafely(t *testing.T) {
	withLibbpfLogger(t, true, false)
	b := &setupWarnings{}
	end := libbpfLog.routeWarnings(b.add)
	const each = 200

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // B's own setup code
		defer wg.Done()
		for i := 0; i < each; i++ {
			b.add(fmt.Sprintf("own %d", i))
		}
	}()
	go func() { // libbpf output on another session's thread
		defer wg.Done()
		for i := 0; i < each; i++ {
			libbpfLog.log(bpf.LibbpfWarnLevel, fmt.Sprintf("libbpf: lib %d\n", i))
		}
	}()
	wg.Wait()
	end()

	got := b.drain()
	// The cap keeps only maxRoutedWarnings of the libbpf lines and adds one
	// summary row; the collector's own adds are never capped.
	if want := each + maxRoutedWarnings + 1; len(got) != want {
		t.Fatalf("collected %d messages, want %d own + %d routed + 1 summary = %d", len(got), each, maxRoutedWarnings, want)
	}
	own := 0
	for _, m := range got {
		if strings.HasPrefix(m, "own ") {
			own++
		}
	}
	if own != each {
		t.Fatalf("collector kept %d of %d own warnings", own, each)
	}
}

// TestRoutedSkippedTracepointWarningsAreDropped: a kernel without dozens of
// the traced syscalls makes libbpf warn once per tracepoint. bpfSetupLog
// already reports those through the probe manager and keeps them out of the
// warning rows, so they must not come back through the libbpf route, while a
// different WARN still does.
func TestRoutedSkippedTracepointWarningsAreDropped(t *testing.T) {
	withLibbpfLogger(t, true, false)
	w := &setupWarnings{}
	end := libbpfLog.routeWarnings(w.add)

	for i := 0; i < 100; i++ {
		libbpfLog.log(bpf.LibbpfWarnLevel,
			fmt.Sprintf("libbpf: prog 'p': failed to determine tracepoint 'syscalls/sys_enter_x%d' perf event ID: No such file or directory\n", i))
	}
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: map 'm': failed to create: Operation not permitted\n")
	end()

	got := w.drain()
	if want := []string{"libbpf: map 'm': failed to create: Operation not permitted"}; !slices.Equal(got, want) {
		t.Fatalf("routed warnings = %q, want only %q", got, want)
	}
}

func TestRoutedWarningsAreCappedWithOneSummary(t *testing.T) {
	withLibbpfLogger(t, true, false)
	w := &setupWarnings{}
	end := libbpfLog.routeWarnings(w.add)

	const total = maxRoutedWarnings + 7
	for i := 0; i < total; i++ {
		libbpfLog.log(bpf.LibbpfWarnLevel, fmt.Sprintf("libbpf: warning %d\n", i))
	}
	end()

	got := w.drain()
	if len(got) != maxRoutedWarnings+1 {
		t.Fatalf("got %d rows, want %d routed plus one summary: %q", len(got), maxRoutedWarnings, got)
	}
	if want := "libbpf: warning 0"; got[0] != want {
		t.Errorf("first row = %q, want %q", got[0], want)
	}
	if summary := got[len(got)-1]; !strings.Contains(summary, "7 further warning(s)") {
		t.Errorf("summary row = %q, want it to count the 7 suppressed lines", summary)
	}
}

// TestRoutedVerifierLogIsTruncatedButHeadlessKeepsItAll: a failed program load
// is one multi-line WARN holding the entire verifier log.
func TestRoutedVerifierLogIsTruncatedButHeadlessKeepsItAll(t *testing.T) {
	verifier := "libbpf: prog 'ior_x': BPF program load failed: Permission denied\n" +
		"libbpf: prog 'ior_x': -- BEGIN PROG LOAD LOG --\n" +
		strings.Repeat("0: (b7) r0 = 0\n", 5000) +
		"libbpf: prog 'ior_x': -- END PROG LOAD LOG --\n"

	withLibbpfLogger(t, true, false)
	w := &setupWarnings{}
	end := libbpfLog.routeWarnings(w.add)
	libbpfLog.log(bpf.LibbpfWarnLevel, verifier)
	end()

	got := w.drain()
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if !strings.HasPrefix(got[0], "libbpf: prog 'ior_x': BPF program load failed: Permission denied") {
		t.Errorf("row lost the failure reason: %q", got[0])
	}
	if !strings.HasSuffix(got[0], "... (5002 more lines)") {
		t.Errorf("row lacks the omitted-lines marker: %q", got[0][max(0, len(got[0])-60):])
	}
	if len(got[0]) > maxRoutedWarningBytes+64 || strings.Contains(got[0], "\n") {
		t.Errorf("row is %d bytes / multi-line, want a short single line", len(got[0]))
	}

	headless := withLibbpfLogger(t, false, false)
	libbpfLog.log(bpf.LibbpfWarnLevel, verifier)
	if headless.String() != verifier {
		t.Errorf("headless stderr got %d bytes, want the full %d-byte verifier log", headless.Len(), len(verifier))
	}
}

func TestShortenWarning(t *testing.T) {
	long := strings.Repeat("é", 400) // 800 bytes, 2 bytes per rune
	tests := []struct {
		name, in, want string
	}{
		{"single short line unchanged", "libbpf: hi", "libbpf: hi"},
		{"multi-line keeps first line", "a\nb\nc", "a ... (2 more lines)"},
		{"long line cut on a rune boundary", long, strings.Repeat("é", 256) + "..."},
		{"long and multi-line", long + "\nx", strings.Repeat("é", 256) + "... ... (1 more lines)"},
	}
	for _, tc := range tests {
		if got := shortenWarning(tc.in, maxRoutedWarningBytes); got != tc.want {
			t.Errorf("%s: shortenWarning = %q, want %q", tc.name, got, tc.want)
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
