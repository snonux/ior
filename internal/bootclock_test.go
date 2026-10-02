package internal

import (
	"go/ast"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// timensOffsetsOf renders a timens_offsets file the way the kernel prints it
// (two right-aligned numeric columns after the clock name).
func timensOffsetsOf(boottimeLine string) string {
	return "monotonic           0         0\n" + boottimeLine + "\n"
}

// TestParseTimensBoottimeOffset covers the offsets a kernel can print. The
// "-2 500000000" case is the one that needs the kernel's convention: a child
// of a namespace given that offset read its clock 1.49 s behind the host's,
// i.e. the nanoseconds count upwards from the (negative) seconds.
func TestParseTimensBoottimeOffset(t *testing.T) {
	cases := map[string]struct {
		content string
		want    int64
	}{
		"host namespace":           {timensOffsetsOf("boottime            0         0"), 0},
		"ahead":                    {timensOffsetsOf("boottime         1000         0"), 1000 * nsPerSec},
		"ahead with nanoseconds":   {timensOffsetsOf("boottime            3 250000000"), 3_250_000_000},
		"behind":                   {timensOffsetsOf("boottime        -1000         0"), -1000 * nsPerSec},
		"behind with nanoseconds":  {timensOffsetsOf("boottime           -2 500000000"), -1_500_000_000},
		"largest the kernel took":  {timensOffsetsOf("boottime   4000000000         0"), 4_000_000_000 * nsPerSec},
		"largest that fits":        {timensOffsetsOf("boottime 9223372035 999999999"), 9_223_372_035_999_999_999},
		"smallest that fits":       {timensOffsetsOf("boottime -9223372035 0"), -9_223_372_035 * nsPerSec},
		"clock id instead of name": {"1 0 0\n7 12 5\n", 12*nsPerSec + 5},
		"boottime line first":      {"boottime 7 0\nmonotonic 99 0\n", 7 * nsPerSec},
		"no trailing newline":      {"monotonic 0 0\nboottime 2 0", 2 * nsPerSec},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseTimensBoottimeOffset(tc.content)
			if err != nil {
				t.Fatalf("parseTimensBoottimeOffset(%q): %v", tc.content, err)
			}
			if got != tc.want {
				t.Fatalf("parseTimensBoottimeOffset(%q) = %d, want %d", tc.content, got, tc.want)
			}
		})
	}
}

// TestParseTimensBoottimeOffsetRejectsWhatNoKernelPrints: a garbled file must
// be an error, never a number - a wrong offset shifts every comparison with a
// record time, which is worse than the uncorrected clock it replaces.
func TestParseTimensBoottimeOffsetRejectsWhatNoKernelPrints(t *testing.T) {
	cases := map[string]string{
		"empty":                    "",
		"no boottime line":         "monotonic 0 0\n",
		"monotonic offset only":    "monotonic 1000 0\nrealtime 5 0\n",
		"seconds missing":          timensOffsetsOf("boottime"),
		"nanoseconds missing":      timensOffsetsOf("boottime 1000"),
		"a fourth field":           timensOffsetsOf("boottime 1000 0 0"),
		"seconds not a number":     timensOffsetsOf("boottime abc 0"),
		"seconds a fraction":       timensOffsetsOf("boottime 1.5 0"),
		"nanoseconds not a number": timensOffsetsOf("boottime 1000 x"),
		"nanoseconds negative":     timensOffsetsOf("boottime 1 -5"),
		"nanoseconds a second":     timensOffsetsOf("boottime 1 1000000000"),
		"seconds past the range":   timensOffsetsOf("boottime 9223372036 0"),
		"seconds below the range":  timensOffsetsOf("boottime -9223372036 0"),
		"seconds past int64":       timensOffsetsOf("boottime 99999999999999999999 0"),
		"binary noise":             "\x00\xff\x00boottime\x00",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := parseTimensBoottimeOffset(content); err == nil {
				t.Fatalf("parseTimensBoottimeOffset(%q) = %d, want an error", content, got)
			}
		})
	}
}

// fakeProcSelf builds a /proc/self stand-in: a timens_offsets file (skipped
// when offsets is "-") and the two time namespace links.
func fakeProcSelf(t *testing.T, offsets, ownNs, childrenNs string) string {
	t.Helper()
	dir := t.TempDir()
	if offsets != "-" {
		if err := os.WriteFile(filepath.Join(dir, "timens_offsets"), []byte(offsets), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"time": ownNs, "time_for_children": childrenNs} {
		if target == "" {
			continue
		}
		if err := os.Symlink(target, filepath.Join(dir, "ns", name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const (
	hostTimeNs  = "time:[4026531834]"
	otherTimeNs = "time:[4026533425]"
)

// TestResolveBootClockDomainTakesTheOffsetOfItsOwnNamespace: the offset is
// used when the file describes the namespace the process itself runs in.
func TestResolveBootClockDomainTakesTheOffsetOfItsOwnNamespace(t *testing.T) {
	for name, tc := range map[string]struct {
		line string
		want int64
	}{
		"host":   {"boottime 0 0", 0},
		"ahead":  {"boottime 1000 0", 1000 * nsPerSec},
		"behind": {"boottime -1000 0", -1000 * nsPerSec},
	} {
		t.Run(name, func(t *testing.T) {
			dir := fakeProcSelf(t, timensOffsetsOf(tc.line), otherTimeNs, otherTimeNs)
			got := resolveBootClockDomain(dir)
			if got.offsetNs != tc.want || got.warning != "" {
				t.Fatalf("resolveBootClockDomain = %+v, want offset %d and no warning", got, tc.want)
			}
		})
	}
}

// TestResolveBootClockDomainWithoutTimeNamespaces: a kernel without time
// namespaces has neither a timens_offsets file nor an ns/time link in an
// otherwise present /proc/self. That is the host's clock, not a failure, so
// nothing is warned about. (A missing file next to an ns/time link, or no
// /proc/self at all, is an unknown offset: see the test below.)
func TestResolveBootClockDomainWithoutTimeNamespaces(t *testing.T) {
	got := resolveBootClockDomain(fakeProcSelf(t, "-", "", ""))
	if got != (bootClockDomain{}) {
		t.Fatalf("resolveBootClockDomain without timens_offsets = %+v, want no offset and no warning", got)
	}
}

// TestResolveBootClockDomainWarnsWhenTheOffsetIsUnknown covers every way the
// offset can stay unknown. Each must leave the clock uncorrected and say so:
// in particular the file's offset must not be used when it describes another
// namespace than the process's own (a task that unshared, or was exec'd by one
// on a kernel that does not switch on exec, keeps the old clock while its
// timens_offsets already shows the new offset).
func TestResolveBootClockDomainWarnsWhenTheOffsetIsUnknown(t *testing.T) {
	ahead := timensOffsetsOf("boottime 1000 0")
	cases := map[string]struct {
		dir  string
		says string
	}{
		"garbled file":           {fakeProcSelf(t, "boottime x y\n", hostTimeNs, hostTimeNs), "boottime seconds"},
		"no boottime line":       {fakeProcSelf(t, "monotonic 0 0\n", hostTimeNs, hostTimeNs), "no boottime line"},
		"file describes another": {fakeProcSelf(t, ahead, hostTimeNs, otherTimeNs), otherTimeNs},
		"own link missing":       {fakeProcSelf(t, ahead, "", otherTimeNs), "ns/time:"},
		"children link missing":  {fakeProcSelf(t, ahead, otherTimeNs, ""), "time_for_children"},
		"unreadable file":        {procSelfWithUnreadableOffsets(t), "timens_offsets"},
		// A kernel with time namespaces always has the file: without it the
		// directory read is not this process's /proc/self.
		"file missing, in a namespace": {fakeProcSelf(t, "-", otherTimeNs, otherTimeNs), "timens_offsets"},
		"file missing, own link only":  {fakeProcSelf(t, "-", hostTimeNs, ""), "timens_offsets"},
		// /proc not mounted, or the /proc of another PID namespace.
		"no /proc/self": {filepath.Join(t.TempDir(), "self"), "timens_offsets"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := resolveBootClockDomain(tc.dir)
			if got.offsetNs != 0 {
				t.Errorf("offset = %d, want 0 (unknown must not correct)", got.offsetNs)
			}
			if !strings.Contains(got.warning, "time namespace") || !strings.Contains(got.warning, tc.says) {
				t.Errorf("warning = %q, want one about the time namespace naming %q", got.warning, tc.says)
			}
		})
	}
}

// procSelfWithUnreadableOffsets is a /proc/self stand-in whose timens_offsets
// exists but cannot be read as a file (it is a directory), which is a read
// error other than "does not exist" whoever runs the test, root included.
func procSelfWithUnreadableOffsets(t *testing.T) string {
	t.Helper()
	dir := fakeProcSelf(t, "-", hostTimeNs, hostTimeNs)
	if err := os.Mkdir(filepath.Join(dir, "timens_offsets"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestBootClockDomainReportsItsWarningOnce: a known offset reports nothing,
// an unknown one hands its warning to the sink exactly once.
func TestBootClockDomainReportsItsWarningOnce(t *testing.T) {
	var got []any
	warn := func(args ...any) { got = append(got, args...) }

	bootClockDomain{offsetNs: 5}.report(warn)
	if len(got) != 0 {
		t.Fatalf("a known offset reported %v, want nothing", got)
	}
	bootClockDomain{warning: "offset unknown"}.report(warn)
	if len(got) != 1 || got[0] != "offset unknown" {
		t.Fatalf("an unknown offset reported %v, want its one warning", got)
	}
}

// TestHostBootNs: the namespace's offset is taken out of the reading, and a
// result that is no time at all is answered like a failed clock read (the
// maximum), never wrapped into a small or huge "time".
func TestHostBootNs(t *testing.T) {
	const reading = 127_791_960_000_000 // 127791.96 s, as read inside +1000 s
	cases := map[string]struct {
		readingNs, offsetNs int64
		want                uint64
	}{
		"no offset":            {reading, 0, reading},
		"ahead of the host":    {reading, 1000 * nsPerSec, 126_791_960_000_000},
		"behind the host":      {reading - 2000*nsPerSec, -1000 * nsPerSec, 126_791_960_000_000},
		"offset past reading":  {reading, reading + 1000, math.MaxUint64},
		"negative reading":     {-5, -10, math.MaxUint64},
		"offset equal reading": {reading, reading, 0},
		"difference overflows": {math.MaxInt64 - 5, -10, math.MaxUint64},
		"difference just fits": {math.MaxInt64 - 10, -10, math.MaxInt64},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := hostBootNs(tc.readingNs, tc.offsetNs); got != tc.want {
				t.Fatalf("hostBootNs(%d, %d) = %d, want %d", tc.readingNs, tc.offsetNs, got, tc.want)
			}
		})
	}
}

// TestBootClockNsReadsTheHostClockOfThisProcess ties bootClockNs to the
// offset of the real /proc/self: two raw CLOCK_BOOTTIME readings around the
// call, each converted with that offset, must bracket it. Outside a time
// namespace the offset is 0 and this is a plain clock check; run inside one
// (unshare -T --boottime N go test) it fails for an uncorrected reading.
func TestBootClockNsReadsTheHostClockOfThisProcess(t *testing.T) {
	domain := resolveBootClockDomain(procSelfDir)
	if domain.warning != "" {
		t.Skipf("boottime offset of this process is unknown: %s", domain.warning)
	}
	before := rawBootClockNs(t)
	got := bootClockNs()
	after := rawBootClockNs(t)

	low, high := hostBootNs(before, domain.offsetNs), hostBootNs(after, domain.offsetNs)
	if got < low || got > high {
		t.Fatalf("bootClockNs() = %d, want within [%d, %d] (raw readings minus the offset %d)",
			got, low, high, domain.offsetNs)
	}
}

// rawBootClockNs is this process's CLOCK_BOOTTIME as the kernel returns it,
// i.e. on the clock of the time namespace the test runs in.
func rawBootClockNs(t *testing.T) int64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatalf("clock_gettime(CLOCK_BOOTTIME): %v", err)
	}
	return ts.Nano()
}

// TestTraceSetupWarnsAboutAnUnknownBootClock pins the one call that makes the
// unknown offset visible: without it ior would compare its uncorrected clock
// with record times and say nothing. It must go to the setup warnings, which
// reach the terminal headless and the TUI's warning line alike - and it must
// get there before wireEventLoopLogging hands them to the loop: the first
// version of this call came after it, into a collector nothing read again, so
// the warning was never shown.
func TestTraceSetupWarnsAboutAnUnknownBootClock(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "runTraceSetup")
	calls := callsNamed(decl, "warnUnknownBootClock")
	if len(calls) != 1 {
		t.Fatalf("trace setup calls warnUnknownBootClock %d times, want exactly once", len(calls))
	}
	assertCallArguments(t, calls[0], []string{"warnSetup"})
	drain := singleBareCall(t, decl, "wireEventLoopLogging")
	if calls[0].Pos() >= drain.Pos() {
		t.Fatalf("warnUnknownBootClock at %s must precede wireEventLoopLogging at %s, "+
			"which drains the setup warnings", fset.Position(calls[0].Pos()), fset.Position(drain.Pos()))
	}
}

// TestTraceSetupCollectsNoWarningAfterTheDrain is the general form of the
// order above: on success the collector is read exactly once, by
// wireEventLoopLogging, so runTraceSetup must not hand warnSetup to anything
// after that call - whatever it added would be lost without a trace.
func TestTraceSetupCollectsNoWarningAfterTheDrain(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "runTraceSetup")
	drain := singleBareCall(t, decl, "wireEventLoopLogging")
	uses := 0
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		ident, isIdent := node.(*ast.Ident)
		if !isIdent || ident.Name != "warnSetup" {
			return true
		}
		uses++
		if ident.Pos() > drain.End() {
			t.Errorf("warnSetup is used at %s, after wireEventLoopLogging drained the setup warnings",
				fset.Position(ident.Pos()))
		}
		return true
	})
	if uses == 0 {
		t.Fatal("runTraceSetup no longer names its warning sink warnSetup; this test checks nothing")
	}
}

// TestUnknownBootClockWarningIsReplayedByTheLoop follows the warning along the
// path trace setup gives it: collected, handed to the loop by
// wireEventLoopLogging, and replayed when the loop starts - to stderr in a
// headless run, exactly once.
func TestUnknownBootClockWarningIsReplayedByTheLoop(t *testing.T) {
	domain := resolveBootClockDomain(fakeProcSelf(t, "boottime x y\n", hostTimeNs, hostTimeNs))
	warnings := &setupWarnings{}
	domain.report(warnings.add)
	el := mustNewEventLoop(t, eventLoopConfig{})
	wireEventLoopLogging(el, newLogger(true), warnings)

	stdout, stderr := captureConsole(t, func() { runCancelledEventLoop(t, el) })

	if stdout != "" {
		t.Fatalf("stdout = %q, want it empty", stdout)
	}
	if n := strings.Count(stderr, "boottime offset of ior's time namespace"); n != 1 {
		t.Fatalf("the warning was printed %d times, want once; stderr:\n%s", n, stderr)
	}
}
