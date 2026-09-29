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

// sleepHarnessTemplate wraps a generateExtraSleep body in a tiny host C
// program so the tests below execute the exact generated C, not a Go model of
// it. bpf_probe_read_user is stubbed with memcpy, and -fwrapv (see
// compileSleepHarness) makes signed overflow wrap like BPF arithmetic does, so
// an unguarded tv_sec*1e9 would reproduce the in-kernel garbage values.
//
// Input lines are "tv_sec tv_nsec flags null"; each prints requested_ns.
const sleepHarnessTemplate = `#include <stdio.h>
#include <string.h>

typedef long long __s64;
struct ior_ctx { unsigned long long args[6]; };
struct ior_ev { __s64 requested_ns; };

static long bpf_probe_read_user(void *dst, unsigned int size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

static __s64 capture(struct ior_ctx *ctx) {
    struct ior_ev storage, *ev = &storage;
%s
    return ev->requested_ns;
}

int main(void) {
    long long sec, nsec;
    unsigned long long flags;
    int null_ptr;
    while (scanf("%%lld %%lld %%llu %%d", &sec, &nsec, &flags, &null_ptr) == 4) {
        struct { __s64 tv_sec; __s64 tv_nsec; } ts = { sec, nsec };
        unsigned long long ptr = null_ptr ? 0 : (unsigned long long)&ts;
        /* nanosleep reads args[0]; clock_nanosleep reads flags from args[1]
           and the request from args[2]. */
        struct ior_ctx ctx = { { ptr, flags, ptr, 0, 0, 0 } };
        printf("%%lld\n", capture(&ctx));
    }
    return 0;
}
`

// sleepCase is one timespec request and the requested_ns the generated
// handler must record for it.
type sleepCase struct {
	name    string
	sec     int64
	nsec    int64
	flags   uint64
	nullPtr bool
	want    int64
}

// relativeSleepCases covers the conversion and its boundaries: exact values,
// the __s64 overflow edge (tv_sec just below/at/above 9223372036), saturation
// of `sleep infinity`, and the invalid timespecs the kernel rejects with
// -EINVAL (which keep the -1 sentinel).
var relativeSleepCases = []sleepCase{
	{name: "zero", want: 0},
	{name: "one second plus", sec: 1, nsec: 500, want: 1_000_000_500},
	{name: "max nsec", sec: 1, nsec: 999_999_999, want: 1_999_999_999},
	{name: "below limit", sec: 9_223_372_035, nsec: 999_999_999, want: 9_223_372_035_999_999_999},
	{name: "exactly S64_MAX", sec: 9_223_372_036, nsec: 854_775_807, want: math.MaxInt64},
	{name: "one ns above limit", sec: 9_223_372_036, nsec: 854_775_808, want: math.MaxInt64},
	{name: "one second above limit", sec: 9_223_372_037, want: math.MaxInt64},
	{name: "1e10 seconds used to wrap negative", sec: 10_000_000_000, want: math.MaxInt64},
	{name: "sleep infinity used to hit -1", sec: math.MaxInt64, nsec: 999_999_999, want: math.MaxInt64},
	{name: "negative nsec", sec: 1, nsec: -1, want: -1},
	{name: "nsec one second", sec: 1, nsec: 1_000_000_000, want: -1},
	{name: "huge sec with invalid nsec", sec: math.MaxInt64, nsec: 1_000_000_000, want: -1},
	{name: "negative sec", sec: -1, want: -1},
	{name: "min sec", sec: math.MinInt64, want: -1},
	{name: "null pointer", sec: 1, nullPtr: true, want: -1},
}

func TestGeneratedNanosleepRequestedNsBoundaries(t *testing.T) {
	runSleepHarness(t, "sys_enter_nanosleep", relativeSleepCases)
}

func TestGeneratedClockNanosleepRequestedNsBoundaries(t *testing.T) {
	cases := append([]sleepCase(nil), relativeSleepCases...)
	cases = append(cases,
		// TIMER_ABSTIME requests are absolute clock values: always unknown,
		// whether or not they would convert or overflow.
		sleepCase{name: "abstime valid", sec: 1, flags: 1, want: -1},
		sleepCase{name: "abstime overflow", sec: math.MaxInt64, nsec: 999_999_999, flags: 1, want: -1},
		// Only the TIMER_ABSTIME bit selects absolute mode.
		sleepCase{name: "other flag bit", sec: 2, flags: 2, want: 2_000_000_000},
	)
	runSleepHarness(t, "sys_enter_clock_nanosleep", cases)
}

// TestCommittedSleepHandlersMatchGenerator guards the committed BPF source:
// the boundary tests above exercise generateExtraSleep, so the checked-in
// generated_tracepoints.c must carry exactly those bodies.
func TestCommittedSleepHandlersMatchGenerator(t *testing.T) {
	source, err := readRepoFile("internal", "c", "generated_tracepoints.c")
	if err != nil {
		t.Fatalf("read generated_tracepoints.c: %v", err)
	}
	for _, name := range []string{"sys_enter_nanosleep", "sys_enter_clock_nanosleep"} {
		requireContains(t, source, generateExtraSleep(name))
	}
}

func runSleepHarness(t *testing.T, tracepoint string, cases []sleepCase) {
	t.Helper()
	binary := compileSleepHarness(t, generateExtraSleep(tracepoint))

	var input strings.Builder
	for _, c := range cases {
		nullPtr := 0
		if c.nullPtr {
			nullPtr = 1
		}
		fmt.Fprintf(&input, "%d %d %d %d\n", c.sec, c.nsec, c.flags, nullPtr)
	}
	cmd := exec.Command(binary)
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run sleep harness: %v", err)
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
			t.Errorf("%s %s {%d, %d} flags=%d: requested_ns = %d, want %d",
				tracepoint, c.name, c.sec, c.nsec, c.flags, got, c.want)
		}
	}
}

// compileSleepHarness builds the harness around body with the host C
// compiler, skipping the test when none is installed.
func compileSleepHarness(t *testing.T, body string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no host C compiler (cc) available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "sleep_harness.c")
	if err := os.WriteFile(src, []byte(fmt.Sprintf(sleepHarnessTemplate, body)), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "sleep_harness")
	out, err := exec.Command(cc, "-O2", "-fwrapv", "-Wall", "-Werror", "-o", binary, src).CombinedOutput()
	if err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}
