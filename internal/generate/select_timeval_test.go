package generate

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// selectHarnessTemplate wraps the committed helper internal/c/poll.c and the
// generated select() poll body in a host C program so the tests execute the
// real C, not a Go model of it. bpf_probe_read_user is stubbed with memcpy;
// the plain build uses -fwrapv so signed overflow wraps like BPF arithmetic
// does, and the sanitizer build (TestSelectTimevalNoSignedOverflow) drops it
// to prove the helper never overflows at all. The two %s verbs take the
// helper source and the body.
//
// Input lines are "tv_sec tv_usec null"; each prints timeout_ns.
const selectHarnessTemplate = `#include <stdio.h>
#include <string.h>

typedef long long __s64;
typedef unsigned long long __u64;
typedef int __s32;
#define POLL_TIMEOUT_INFINITE_NS -1
#define POLL_TIMEOUT_UNKNOWN_NS -2
#define POLL_EVENT_SCHEMA_VERSION 1
struct ior_ctx { unsigned long long args[6]; };
struct ior_ev { __s64 timeout_ns; __s32 nfds; __s32 fd; int schema_version; };

static long bpf_probe_read_user(void *dst, unsigned int size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

%s

static __s64 capture(struct ior_ctx *ctx) {
    struct ior_ev storage, *ev = &storage;
%s
    return ev->timeout_ns;
}

int main(void) {
    long long sec, usec;
    int null_ptr;
    while (scanf("%%lld %%lld %%d", &sec, &usec, &null_ptr) == 3) {
        struct { __s64 tv_sec; __s64 tv_usec; } tv = { sec, usec };
        unsigned long long ptr = null_ptr ? 0 : (unsigned long long)&tv;
        /* select(nfds, r, w, e, timeout): the timeout is args[4]. */
        struct ior_ctx ctx = { { 0, 0, 0, 0, ptr, 0 } };
        printf("%%lld\n", capture(&ctx));
    }
    return 0;
}
`

// selectCase is one struct timeval and the timeout_ns the generated handler
// must record for it.
type selectCase struct {
	name    string
	sec     int64
	usec    int64
	nullPtr bool
	want    int64
}

// selectTimeoutCases follows kern_select(): tv_usec is normalised into
// seconds and nanoseconds before validation, and only a negative result is
// -EINVAL (recorded as the unknown sentinel -2 together with unreadable
// timeouts).
var selectTimeoutCases = []selectCase{
	{name: "zero", want: 0},
	{name: "plain", sec: 1, usec: 500, want: 1_000_500_000},
	{name: "max usec", sec: 1, usec: 999_999, want: 1_999_999_000},
	// Live evidence for the bug: select(0,...,{0,1500000}) slept 1.5 s.
	{name: "usec 1.5 s", usec: 1_500_000, want: 1_500_000_000},
	{name: "usec exactly 1 s", usec: 1_000_000, want: 1_000_000_000},
	{name: "sec plus usec carry", sec: 2, usec: 3_250_000, want: 5_250_000_000},
	{name: "negative sec rescued by usec", sec: -1, usec: 2_000_000, want: 1_000_000_000},
	{name: "negative usec whole seconds", sec: 5, usec: -1_000_000, want: 4_000_000_000},
	{name: "negative usec to zero", sec: 1, usec: -1_000_000, want: 0},
	{name: "huge usec below limit", usec: 9_223_372_036_000_000, want: 9_223_372_036_000_000_000},
	// The largest representable timeout. tv_usec is whole microseconds, so the
	// remainder is a multiple of 1000 ns and the largest one that fits is
	// 854775000 ns, not the 854775807 of IOR_TIMEVAL_MAX_SEC_REM_NS: usec
	// 854775 is the last accepted value at the boundary second and 854776 the
	// first rejected one. These two cases pin the remainder bound from both
	// sides; a bound below 854775000 or at/above 854775999 flips one of them.
	{name: "largest representable timeout", sec: 9_223_372_036, usec: 854_775, want: 9_223_372_036_854_775_000},
	{name: "one usec above largest", sec: 9_223_372_036, usec: 854_776, want: -2},
	{name: "usec carry above limit", sec: 9_223_372_036, usec: 1_000_000, want: -2},
	// The same boundary reached through the usec carry, so the check applies
	// to the normalised value and not to the raw fields.
	{name: "carry to largest", sec: 9_223_372_035, usec: 1_854_775, want: 9_223_372_036_854_775_000},
	{name: "carry one usec above largest", sec: 9_223_372_035, usec: 1_854_776, want: -2},
	{name: "negative usec to boundary second", sec: 9_223_372_037, usec: -1_000_000, want: 9_223_372_036_000_000_000},
	{name: "negative usec above boundary second", sec: 9_223_372_038, usec: -1_000_000, want: -2},
	{name: "huge sec", sec: 10_000_000_000, want: -2},
	{name: "huge sec and usec", sec: math.MaxInt64, usec: math.MaxInt64, want: -2},
	{name: "min sec", sec: math.MinInt64, want: -2},
	{name: "min usec", usec: math.MinInt64, want: -2},
	{name: "negative sec", sec: -1, want: -2},
	{name: "negative sec, small usec", sec: -1, usec: 999_999, want: -2},
	{name: "negative usec", sec: 5, usec: -1, want: -2},
	{name: "negative usec not a whole second", sec: 5, usec: -1_500_000, want: -2},
	{name: "negative result after carry", sec: 1, usec: -2_000_000, want: -2},
	{name: "null pointer means infinite", sec: 1, nullPtr: true, want: -1},
}

func TestGeneratedSelectTimevalNormalisation(t *testing.T) {
	binary := compileSelectHarness(t, generateExtraPoll("sys_enter_select"), "-fwrapv")
	checkSelectCases(t, binary, selectTimeoutCases)
}

// overflowCases are timevals whose tv_sec is near the int64 limits, so an
// unclamped tv_sec + carry or tv_sec - carry would overflow a signed __s64.
// Every one is invalid or out of range (-2): the clamp on tv_sec in
// ior_timeval_timeout_ns exists purely to keep that addition defined.
var overflowCases = []selectCase{
	{name: "max sec, max usec", sec: math.MaxInt64, usec: math.MaxInt64, want: -2},
	{name: "max sec, one carry", sec: math.MaxInt64, usec: 1_000_000, want: -2},
	{name: "max sec, small usec", sec: math.MaxInt64, usec: 1, want: -2},
	{name: "min sec, negative whole second", sec: math.MinInt64, usec: -1_000_000, want: -2},
	{name: "min sec, min usec", sec: math.MinInt64, usec: math.MinInt64, want: -2},
	{name: "min sec, positive carry", sec: math.MinInt64, usec: 1_000_000, want: -2},
	{name: "near max sec, big carry", sec: math.MaxInt64 - 1, usec: math.MaxInt64, want: -2},
	{name: "just above clamp, carry", sec: 1<<62 + 1, usec: math.MaxInt64, want: -2},
	{name: "just below clamp, carry", sec: 1<<62 - 1, usec: math.MaxInt64, want: -2},
}

// TestSelectTimevalNoSignedOverflow rebuilds the harness without -fwrapv and
// with UBSan aborting on signed overflow. The normal build wraps silently, so
// it cannot tell whether the +-2^62 clamp of tv_sec in poll.c is needed (a
// wrapped sum still lands outside the valid range and yields -2). Here an
// unclamped addition on the cases above is a sanitizer report and a failed
// run, so removing the clamp fails this test. All the ordinary cases must stay
// clean too.
func TestSelectTimevalNoSignedOverflow(t *testing.T) {
	flags := []string{"-fsanitize=signed-integer-overflow", "-fno-sanitize-recover=all", "-fno-wrapv"}
	if !sanitizerAvailable(t, flags) {
		t.Skip("host C compiler cannot build with -fsanitize=signed-integer-overflow")
	}
	binary := compileSelectHarness(t, generateExtraPoll("sys_enter_select"), flags...)
	cases := append(append([]selectCase{}, selectTimeoutCases...), overflowCases...)
	checkSelectCases(t, binary, cases)
}

// checkSelectCases feeds the cases to the harness and compares each result.
// The harness runs once for all cases; a sanitizer abort surfaces as a run
// error carrying the UBSan report on stderr.
func checkSelectCases(t *testing.T, binary string, cases []selectCase) {
	t.Helper()
	var input strings.Builder
	for _, c := range cases {
		nullPtr := 0
		if c.nullPtr {
			nullPtr = 1
		}
		fmt.Fprintf(&input, "%d %d %d\n", c.sec, c.usec, nullPtr)
	}
	cmd := exec.Command(binary)
	cmd.Stdin = strings.NewReader(input.String())
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run select harness: %v\n%s", err, stderr.String())
	}
	lines := strings.Fields(string(out))
	if len(lines) != len(cases) {
		t.Fatalf("harness printed %d results for %d cases: %q", len(lines), len(cases), out)
	}
	for i, c := range cases {
		got, err := strconv.ParseInt(lines[i], 10, 64)
		if err != nil {
			t.Fatalf("%s: parse %q: %v", c.name, lines[i], err)
		}
		if got != c.want {
			t.Errorf("select %s {%d, %d}: timeout_ns = %d, want %d", c.name, c.sec, c.usec, got, c.want)
		}
	}
}

// TestCommittedSelectHandlerMatchesGenerator guards the committed BPF source:
// the test above exercises generateExtraPoll, so the checked-in
// generated_tracepoints.c must carry exactly that body.
func TestCommittedSelectHandlerMatchesGenerator(t *testing.T) {
	source, err := readRepoFile("internal", "c", "generated_tracepoints.c")
	if err != nil {
		t.Fatalf("read generated_tracepoints.c: %v", err)
	}
	requireContains(t, source, generateExtraPoll("sys_enter_select"))
}

// hostCC returns the host C compiler, skipping the test when none is
// installed.
func hostCC(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no host C compiler (cc) available")
	}
	return cc
}

// sanitizerAvailable reports whether the host compiler can build and run a
// trivial program with the given sanitizer flags (the compiler may lack the
// sanitizer runtime library), so callers skip instead of failing.
func sanitizerAvailable(t *testing.T, flags []string) bool {
	t.Helper()
	cc := hostCC(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "probe.c")
	if err := os.WriteFile(src, []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatalf("write sanitizer probe: %v", err)
	}
	binary := filepath.Join(dir, "probe")
	args := append(append([]string{}, flags...), "-o", binary, src)
	if err := exec.Command(cc, args...).Run(); err != nil {
		return false
	}
	return exec.Command(binary).Run() == nil
}

// compileSelectHarness builds the harness around poll.c and body with the host
// C compiler (skipping the test when none is installed). extraFlags select the
// integer-overflow behaviour: -fwrapv, or the sanitizer flags.
func compileSelectHarness(t *testing.T, body string, extraFlags ...string) string {
	t.Helper()
	helper, err := readRepoFile("internal", "c", "poll.c")
	if err != nil {
		t.Fatalf("read poll.c: %v", err)
	}
	cc := hostCC(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "select_harness.c")
	if err := os.WriteFile(src, []byte(fmt.Sprintf(selectHarnessTemplate, helper, body)), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "select_harness")
	args := append([]string{"-O2", "-Wall", "-Werror"}, extraFlags...)
	args = append(args, "-o", binary, src)
	if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}
