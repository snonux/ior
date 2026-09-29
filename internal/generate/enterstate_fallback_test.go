package generate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The syscall accounting in internal/c/filter.c keeps syscall_aggregate_map
// and the ring-buffer stream an exact partition of the invocations, also when
// syscall_enter_state_map has no entry for a sys_exit ("Enter state and its
// two fallbacks" there). Instead of pinning source text, these tests cut the
// real accounting functions out of filter.c, compile them with the host C
// compiler against simulated BPF maps, and drive them through the scenarios
// that matter: sampling, full maps, failed replacements, clone-child and
// mismatched exits, untimed counts and min/max seeding. Each scenario is also
// run against mutated sources, so the suite is shown to catch the
// regressions it exists for.

// accountingFunctions are the filter.c functions the harness compiles, in
// dependency order.
var accountingFunctions = []string{
	"ior_is_errno_ret",
	"ior_histogram_bucket_index",
	"ior_aggregate_has_timed_samples",
	"ior_update_syscall_aggregate",
	"ior_count_untimed_syscall",
	"ior_sampling_rate",
	"ior_sample_rate_emits",
	"ior_on_enter_state_lost",
	"ior_stateless_exit_emits",
	"ior_on_syscall_enter",
	"ior_on_syscall_exit",
}

// accountingHarnessTemplate provides the BPF helpers the functions use as a
// small in-process map simulation. Updates of a new key fail with -E2BIG once
// the map holds cap entries (as a full BPF hash does); "fail 1" makes every
// update of the enter-state map fail with -EBUSY, including replacements.
// Every command prints exactly one line.
const accountingHarnessTemplate = `#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define BPF_ANY 0

%s
%s

#define SIM_SLOTS 64
struct sim_map {
    unsigned cap, vsize;
    int fail;
    int used[SIM_SLOTS];
    __u32 keys[SIM_SLOTS];
    unsigned char vals[SIM_SLOTS][128];
};
static struct sim_map syscall_enter_state_map = { SIM_SLOTS, sizeof(struct syscall_enter_state) };
static struct sim_map syscall_aggregate_map = { SIM_SLOTS, sizeof(struct syscall_aggregate) };
static struct sim_map syscall_sampling_rate_map = { SIM_SLOTS, sizeof(__u32) };
static __u32 sim_rand;

/* filter.c's stand-in for the kernel errno must match it. */
_Static_assert(IOR_E2BIG == E2BIG, "IOR_E2BIG differs from E2BIG");

static int sim_find(struct sim_map *m, __u32 key) {
    for (int i = 0; i < SIM_SLOTS; i++)
        if (m->used[i] && m->keys[i] == key)
            return i;
    return -1;
}

static unsigned sim_len(struct sim_map *m) {
    unsigned n = 0;
    for (int i = 0; i < SIM_SLOTS; i++)
        n += m->used[i] != 0;
    return n;
}

static void *bpf_map_lookup_elem(void *map, const void *key) {
    struct sim_map *m = map;
    int i = sim_find(m, *(const __u32 *)key);
    return i < 0 ? NULL : m->vals[i];
}

static long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags) {
    struct sim_map *m = map;
    __u32 k = *(const __u32 *)key;
    int i = sim_find(m, k);
    (void)flags;
    if (m->fail)
        return -EBUSY;
    if (i < 0) {
        if (sim_len(m) >= m->cap)
            return -E2BIG;
        for (i = 0; m->used[i]; i++)
            ;
        m->used[i] = 1;
        m->keys[i] = k;
    }
    memcpy(m->vals[i], value, m->vsize);
    return 0;
}

static long bpf_map_delete_elem(void *map, const void *key) {
    struct sim_map *m = map;
    int i = sim_find(m, *(const __u32 *)key);
    if (i < 0)
        return -ENOENT;
    m->used[i] = 0;
    return 0;
}

static __u32 bpf_get_prandom_u32(void) {
    return sim_rand;
}

%s

static void print_aggregate(__u32 id) {
    struct syscall_aggregate *a = bpf_map_lookup_elem(&syscall_aggregate_map, &id);
    if (!a) {
        printf("none\n");
        return;
    }
    printf("count=%%llu errors=%%llu total=%%llu min=%%llu max=%%llu hist=%%llu,%%llu,%%llu,%%llu,%%llu,%%llu,%%llu,%%llu\n",
           a->count, a->errors, a->total_duration_ns, a->min_duration_ns, a->max_duration_ns,
           a->duration_histogram[0], a->duration_histogram[1], a->duration_histogram[2],
           a->duration_histogram[3], a->duration_histogram[4], a->duration_histogram[5],
           a->duration_histogram[6], a->duration_histogram[7]);
}

int main(void) {
    char cmd[16];
    unsigned long long a, b, c, d;
    long long ret;
    while (scanf("%%15s", cmd) == 1) {
        if (!strcmp(cmd, "rate") && scanf("%%llu %%llu", &a, &b) == 2) {
            __u32 k = a, v = b;
            bpf_map_update_elem(&syscall_sampling_rate_map, &k, &v, BPF_ANY);
            printf("ok\n");
        } else if (!strcmp(cmd, "cap") && scanf("%%llu", &a) == 1) {
            syscall_enter_state_map.cap = a;
            printf("ok\n");
        } else if (!strcmp(cmd, "fail") && scanf("%%llu", &a) == 1) {
            syscall_enter_state_map.fail = a;
            printf("ok\n");
        } else if (!strcmp(cmd, "rand") && scanf("%%llu", &a) == 1) {
            sim_rand = a;
            printf("ok\n");
        } else if (!strcmp(cmd, "enter") && scanf("%%llu %%llu %%llu", &a, &b, &c) == 3) {
            printf("emit=%%d\n", ior_on_syscall_enter(a, b, c));
        } else if (!strcmp(cmd, "exit") && scanf("%%llu %%llu %%lld %%llu", &a, &b, &ret, &d) == 4) {
            printf("emit=%%d\n", ior_on_syscall_exit(a, b, ret, d));
        } else if (!strcmp(cmd, "agg") && scanf("%%llu", &a) == 1) {
            print_aggregate(a);
        } else if (!strcmp(cmd, "state") && scanf("%%llu", &a) == 1) {
            __u32 k = a;
            struct syscall_enter_state *s = bpf_map_lookup_elem(&syscall_enter_state_map, &k);
            if (s)
                printf("state id=%%u emit=%%u\n", s->enter_trace_id, s->emit_event);
            else
                printf("nostate\n");
        } else {
            printf("bad command %%s\n", cmd);
            return 1;
        }
    }
    return 0;
}
`

// accountingStep is one harness command and the line it must print.
type accountingStep struct {
	cmd  string
	want string
}

type accountingScenario struct {
	name  string
	steps []accountingStep
}

const (
	accAggNone = "none"
	accEmit0   = "emit=0"
	accEmit1   = "emit=1"
	accOK      = "ok"
)

// accountingScenarios use trace IDs 100 (rate 0), 200 (rate 1, also the
// default of an unconfigured ID) and 300 (rate 4). A duration of 5000ns lands
// in histogram bucket 1 (1us..10us), 50000ns in bucket 2.
var accountingScenarios = []accountingScenario{
	{name: "partition by rate", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK},
		{"enter 1 200 1000", accEmit1}, {"exit 1 200 0 6000", accEmit1}, {"agg 200", accAggNone},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -2 6000", accEmit0},
		{"agg 100", "count=1 errors=1 total=5000 min=5000 max=5000 hist=0,1,0,0,0,0,0,0"},
		{"rand 0", accOK}, {"enter 1 300 1000", accEmit1}, {"exit 1 300 0 6000", accEmit1}, {"agg 300", accAggNone},
		{"rand 1", accOK}, {"enter 1 300 1000", accEmit0}, {"exit 1 300 0 6000", accEmit0},
		{"agg 300", "count=1 errors=0 total=5000 min=5000 max=5000 hist=0,1,0,0,0,0,0,0"},
		{"state 1", "nostate"},
	}},
	// A clone/fork child's first return has no enter state: never counted,
	// and emitted only where a rate-1 enter would have been.
	{name: "stateless exit follows the rate", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK},
		{"exit 7 100 0 5000", accEmit0}, {"exit 7 300 0 5000", accEmit0}, {"exit 7 200 0 5000", accEmit1},
		{"agg 100", accAggNone}, {"agg 300", accAggNone}, {"agg 200", accAggNone},
	}},
	// A leftover entry of another syscall is dropped and the exit treated
	// as stateless, not paired with the foreign state.
	{name: "mismatched exit is stateless", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"enter 1 200 1000", accEmit1}, {"exit 1 100 0 6000", accEmit0},
		{"state 1", "nostate"}, {"agg 100", accAggNone}, {"agg 200", accAggNone},
	}},
	// Enter-state map full: a new tid's write fails. Rate 1 still emits the
	// pair; other rates count the invocation once, untimed, at enter.
	{name: "full enter-state map", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK}, {"cap 1", accOK}, {"rand 0", accOK},
		{"enter 1 200 1000", accEmit1},
		{"enter 2 200 1000", accEmit1}, {"exit 2 200 0 6000", accEmit1}, {"agg 200", accAggNone},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 6000", accEmit0},
		{"agg 100", "count=1 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
		{"enter 2 300 1000", accEmit0}, {"exit 2 300 0 6000", accEmit0},
		{"agg 300", "count=1 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
		{"enter 2 100 1000", accEmit0},
		{"agg 100", "count=2 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
	}},
	// A failed replacement must not leave the tid's older entry behind: its
	// exit would otherwise aggregate the call a second time.
	{name: "failed replacement drops the old entry", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"enter 1 100 1000", accEmit0}, {"state 1", "state id=100 emit=0"},
		{"fail 1", accOK}, {"enter 1 100 2000", accEmit0}, {"state 1", "nostate"},
		{"fail 0", accOK}, {"exit 1 100 0 9000", accEmit0},
		{"agg 100", "count=1 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
	}},
	// Untimed counts must not seed or pin the minimum; the first timed
	// sample does, later ones only lower it.
	{name: "untimed then timed seeds min", steps: []accountingStep{
		{"rate 100 0", accOK}, {"cap 1", accOK},
		{"enter 1 200 0", accEmit1},
		{"enter 2 100 0", accEmit0}, {"exit 2 100 0 0", accEmit0},
		{"cap 64", accOK},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 51000", accEmit0},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 6000", accEmit0},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 81000", accEmit0},
		{"agg 100", "count=4 errors=0 total=135000 min=5000 max=80000 hist=0,1,2,0,0,0,0,0"},
	}},
	{name: "timed then untimed keeps min", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 0 51000", accEmit0},
		{"cap 1", accOK}, {"enter 3 200 0", accEmit1}, {"enter 2 100 0", accEmit0},
		{"agg 100", "count=2 errors=0 total=50000 min=50000 max=50000 hist=0,0,1,0,0,0,0,0"},
	}},
}

func TestSyscallAccountingScenarios(t *testing.T) {
	filterC, mapsH := readAccountingSources(t)
	binary := compileAccountingHarness(t, filterC, mapsH)
	for _, sc := range accountingScenarios {
		t.Run(sc.name, func(t *testing.T) {
			for _, problem := range runAccountingScenario(t, binary, sc) {
				t.Error(problem)
			}
		})
	}
}

// TestSyscallAccountingScenariosCatchRegressions compiles plausible
// regressions of filter.c and requires at least one scenario to fail on each.
func TestSyscallAccountingScenariosCatchRegressions(t *testing.T) {
	filterC, mapsH := readAccountingSources(t)
	mutations := map[string][2]string{
		"enter ignores a failed write": {
			"        return ior_on_enter_state_lost(enter_trace_id, rate);\n    }",
			"    }",
		},
		"delete skipped for every error": {
			"if (err != -IOR_E2BIG)",
			"if (0)",
		},
		"failed replacement keeps the old entry": {
			"            bpf_map_delete_elem(&syscall_enter_state_map, &tid);\n",
			"            (void)tid;\n",
		},
		"stateless exit always emits": {
			"if (!state)\n        return ior_stateless_exit_emits(enter_trace_id);",
			"if (!state)\n        return 1;",
		},
		"lost state emits at every rate": {
			"if (rate == 1)\n        return 1;\n    ior_count_untimed_syscall(",
			"if (rate != 0)\n        return 1;\n    ior_count_untimed_syscall(",
		},
		"mismatched exit uses the foreign state": {
			"if (state->enter_trace_id != enter_trace_id) {",
			"if (0) {",
		},
		"untimed fresh row counts twice": {
			"fresh.count = 1;\n    bpf_map_update_elem(&syscall_aggregate_map, &enter_trace_id, &fresh, BPF_ANY);\n}\n\n// ior_sampling_rate",
			"fresh.count = 2;\n    bpf_map_update_elem(&syscall_aggregate_map, &enter_trace_id, &fresh, BPF_ANY);\n}\n\n// ior_sampling_rate",
		},
		"untimed count touches the histogram": {
			"        existing->count += 1;\n        return;\n    }\n\n    fresh.count = 1;\n    bpf_map_update_elem",
			"        existing->count += 1;\n        existing->duration_histogram[0] += 1;\n        return;\n    }\n\n    fresh.count = 1;\n    bpf_map_update_elem",
		},
		"timed check looks at count": {
			"    if (agg->max_duration_ns)\n        return 1;",
			"    if (agg->count)\n        return 1;",
		},
	}
	for name, m := range mutations {
		t.Run(name, func(t *testing.T) {
			if strings.Count(filterC, m[0]) != 1 {
				t.Fatalf("mutation anchor %q must occur exactly once in filter.c", m[0])
			}
			binary := compileAccountingHarness(t, strings.Replace(filterC, m[0], m[1], 1), mapsH)
			for _, sc := range accountingScenarios {
				if len(runAccountingScenario(t, binary, sc)) > 0 {
					return
				}
			}
			t.Fatal("every scenario passed on the mutated source")
		})
	}
}

// TestSyscallAggregateStoreOrder pins what the single-threaded harness cannot
// observe: ior_update_syscall_aggregate decides the min seeding before it
// bumps the histogram, and stores count last behind a compiler barrier, so a
// torn userspace read shows the histogram ahead of count, never behind
// (internal/syscall_aggregate_consumer.go relies on that).
func TestSyscallAggregateStoreOrder(t *testing.T) {
	filterC, mapsH := readAccountingSources(t)
	if problem := aggregateStoreOrderProblem(filterC); problem != "" {
		t.Fatal(problem)
	}
	// Storing count last only helps because userspace copies it first: it
	// must stay the first field of the struct (see maps.h).
	if problem := countFirstFieldProblem(mapsH); problem != "" {
		t.Fatal(problem)
	}
	moved := strings.Replace(mapsH, "    __u64 count;\n    __u64 errors;\n", "    __u64 errors;\n    __u64 count;\n", 1)
	if moved == mapsH || countFirstFieldProblem(moved) == "" {
		t.Error("count-first check accepted a struct with count moved down")
	}
	mutations := map[string][2]string{
		"count stored first": {
			"        existing->total_duration_ns += duration_ns;\n",
			"        existing->count += 1;\n        existing->total_duration_ns += duration_ns;\n",
		},
		"min decided after the histogram bump": {
			"        existing->duration_histogram[bucket_idx] += 1;\n",
			"        existing->duration_histogram[bucket_idx] += 1;\n        if (!ior_aggregate_has_timed_samples(existing)) existing->min_duration_ns = duration_ns;\n",
		},
		"no compiler barrier": {
			"        asm volatile(\"\" ::: \"memory\");\n",
			"",
		},
	}
	for name, m := range mutations {
		if strings.Count(filterC, m[0]) != 1 {
			t.Fatalf("%s: anchor %q must occur exactly once", name, m[0])
		}
		if aggregateStoreOrderProblem(strings.Replace(filterC, m[0], m[1], 1)) == "" {
			t.Errorf("%s: store-order check accepted the regression", name)
		}
	}
}

// countFirstFieldProblem reports when count is not the first member of struct
// syscall_aggregate in maps.h, or returns "".
func countFirstFieldProblem(mapsH string) string {
	m := regexp.MustCompile(`struct syscall_aggregate \{\s*([^;]*);`).FindStringSubmatch(stripCComments(mapsH))
	if m == nil {
		return "struct syscall_aggregate not found in maps.h"
	}
	if strings.Join(strings.Fields(m[1]), " ") != "__u64 count" {
		return fmt.Sprintf("first field of struct syscall_aggregate is %q, want __u64 count", m[1])
	}
	return ""
}

// aggregateStoreOrderProblem describes a store-order violation in the
// existing-row branch of ior_update_syscall_aggregate, or returns "".
func aggregateStoreOrderProblem(filterC string) string {
	fn := extractCFunction(stripCComments(filterC), "ior_update_syscall_aggregate")
	start := strings.Index(fn, "if (existing) {")
	end := strings.Index(fn, "fresh.count = 1;")
	if fn == "" || start < 0 || end < start {
		return "cannot isolate the existing-row branch of ior_update_syscall_aggregate"
	}
	branch := fn[start:end]
	lines := strings.Split(branch, "\n")
	var stores []string
	for _, line := range lines {
		if strings.Contains(line, "existing->") || strings.Contains(line, "asm volatile") {
			stores = append(stores, strings.TrimSpace(line))
		}
	}
	if len(stores) < 3 || stores[len(stores)-1] != "existing->count += 1;" ||
		stores[len(stores)-2] != `asm volatile("" ::: "memory");` {
		return fmt.Sprintf("count must be the last store, right behind a compiler barrier: %q", stores)
	}
	if strings.Count(branch, "existing->count") != 1 {
		return "count must be stored exactly once"
	}
	seed := strings.Index(branch, "ior_aggregate_has_timed_samples(existing)")
	hist := strings.Index(branch, "existing->duration_histogram[bucket_idx] += 1;")
	if seed < 0 || hist < 0 || seed > hist || strings.Count(branch, "ior_aggregate_has_timed_samples") != 1 {
		return "the min seeding decision must precede the histogram bump"
	}
	return ""
}

func readAccountingSources(t *testing.T) (string, string) {
	t.Helper()
	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatalf("read filter.c: %v", err)
	}
	mapsH, err := readCSource("maps.h")
	if err != nil {
		t.Fatalf("read maps.h: %v", err)
	}
	return filterC, mapsH
}

var cDefineRE = regexp.MustCompile(`(?m)^#define IOR_(HISTOGRAM_BUCKETS|MAX_ERRNO|E2BIG) .*$`)

// accountingHarnessSource assembles the harness from the defines and
// functions of filter.c and the two state structs of maps.h.
func accountingHarnessSource(filterC, mapsH string) (string, error) {
	defines := strings.Join(cDefineRE.FindAllString(filterC, -1), "\n")
	// Comments may hold braces that would derail extractCFunction.
	code := stripCComments(filterC)
	var structs []string
	for _, name := range []string{"syscall_enter_state", "syscall_aggregate"} {
		re := regexp.MustCompile(`(?s)struct ` + name + ` \{.*?\n\};`)
		s := re.FindString(mapsH)
		if s == "" {
			return "", fmt.Errorf("struct %s not found in maps.h", name)
		}
		structs = append(structs, s)
	}
	var funcs []string
	for _, name := range accountingFunctions {
		fn := extractCFunction(code, name)
		if fn == "" {
			return "", fmt.Errorf("function %s not found in filter.c", name)
		}
		funcs = append(funcs, fn)
	}
	return fmt.Sprintf(accountingHarnessTemplate, defines, strings.Join(structs, "\n\n"),
		strings.Join(funcs, "\n\n")), nil
}

// extractCFunction returns the full definition of the static inline function
// name: from its signature to the brace closing its body.
func extractCFunction(source, name string) string {
	re := regexp.MustCompile(`(?m)^static __always_inline [^\n(]*\b` + name + `\(`)
	loc := re.FindStringIndex(source)
	if loc == nil {
		return ""
	}
	open := strings.IndexByte(source[loc[1]:], '{')
	if open < 0 {
		return ""
	}
	depth := 0
	for i := loc[1] + open; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[loc[0] : i+1]
			}
		}
	}
	return ""
}

func compileAccountingHarness(t *testing.T, filterC, mapsH string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no host C compiler (cc) available")
	}
	src, err := accountingHarnessSource(filterC, mapsH)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "accounting_harness.c")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "accounting_harness")
	out, err := exec.Command(cc, "-O2", "-Wall", "-Werror", "-o", binary, srcPath).CombinedOutput()
	if err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}

// runAccountingScenario runs sc in a fresh harness process and returns one
// message per step whose output differs from the expectation.
func runAccountingScenario(t *testing.T, binary string, sc accountingScenario) []string {
	t.Helper()
	cmds := make([]string, len(sc.steps))
	for i, step := range sc.steps {
		cmds[i] = step.cmd
	}
	cmd := exec.Command(binary)
	cmd.Stdin = strings.NewReader(strings.Join(cmds, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		return []string{fmt.Sprintf("%s: harness failed: %v\n%s", sc.name, err, out)}
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var problems []string
	for i, step := range sc.steps {
		line := "<missing>"
		if i < len(got) {
			line = got[i]
		}
		if line != step.want {
			problems = append(problems, fmt.Sprintf("%s: step %d %q printed %q, want %q", sc.name, i, step.cmd, line, step.want))
		}
	}
	return problems
}
