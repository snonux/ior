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

// The registered-ring capture (internal/c/iouring.c, task js2) decides by an
// opcode whether a call is its business, writes enter state of its own at
// rate 1 and reads a caller-sized array out of user memory. These tests
// compile the committed helpers with the host C compiler against a simulated
// enter-state map, user buffer and ring buffer and run them, instead of
// pinning their source text. Each property is also checked against a mutated
// helper, so the suite is shown to catch the regression it is for.

// ringFdsHarnessTemplate wraps iouring.c. The %s verbs take the ring-fds
// #defines and struct ring_fds_event from types.h, struct syscall_enter_state
// from maps.h and the helper source.
//
// The enter-state map is one slot (present or not). User memory is the
// buffer user[], of which the first `mapped` bytes are readable:
// bpf_probe_read_user fails as a whole - zero-filling its destination, like
// the kernel helper - for a range that leaves them. The buffer holds 20
// array elements, element i being {offset 100+i, resv 7, data 200+i}. The
// record is preset to 0xee, the stale bytes a ring-buffer reservation holds,
// and followed by a guard the helpers must not touch.
//
// Input lines (each prints one line, flushed at once so that a helper that
// crashes later still leaves the earlier answers):
//
//	opcode <opcode argument>
//	stash  <present> <entry id> <entry start> <emits> <opcode argument>
//	read   <mapped> <ret>
//	emit   <opcode> <mapped> <ret> <ring full>
//
// stash runs as tid 5, trace ID 9, clock read 1000, array pointer 4242.
const ringFdsHarnessTemplate = `#include <stdio.h>
#include <string.h>

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;
#define __always_inline inline __attribute__((always_inline))
#define BPF_ANY 0

%s
%s
%s

static __u8 user[4096];
static unsigned mapped, max_read, reads, drops, ring_full, submitted, updates;
static int event_map, syscall_enter_state_map;
static struct { struct ring_fds_event ev; __u8 guard[64]; } ring;
static struct syscall_enter_state slot;
static int slot_present;

static long bpf_probe_read_user(void *dst, unsigned int size, const void *src) {
    const __u8 *p = src;
    reads++;
    if (size > max_read)
        max_read = size;
    if (p < user || size > mapped || p + size > user + mapped) {
        if (size <= IOR_RING_FDS_BYTES)
            memset(dst, 0, size);
        return -14;
    }
    memcpy(dst, src, size);
    return 0;
}
static void *bpf_ringbuf_reserve(void *map, unsigned long size, unsigned long flags) {
    return ring_full || size != sizeof(ring.ev) ? 0 : &ring.ev;
}
static void bpf_ringbuf_submit(void *ev, unsigned long flags) { submitted++; }
static void ior_count_ringbuf_drop(void) { drops++; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
    return slot_present && *(const __u32 *)key == 5 ? &slot : 0;
}
static long bpf_map_update_elem(void *map, const void *key, const void *value, unsigned long flags) {
    updates++;
    slot = *(const struct syscall_enter_state *)value;
    slot_present = 1;
    return 0;
}

%s

static void fill_user(void) {
    unsigned i;
    memset(user, 0, sizeof(user));
    for (i = 0; i < 20; i++) {
        __u32 offset = 100 + i, resv = 7;
        __u64 data = 200 + i;
        memcpy(user + i * 16, &offset, 4);
        memcpy(user + i * 16 + 4, &resv, 4);
        memcpy(user + i * 16 + 8, &data, 8);
    }
}

/* updates_report prints how many leading elements are the caller's, whether
 * everything after them is zero, the guard and the reads issued. */
static void updates_report(const __u8 *got) {
    unsigned prefix = 0, i, clean = 1, guard = 1;
    while (prefix < IOR_RING_FDS_MAX && !memcmp(got + prefix * 16, user + prefix * 16, 16))
        prefix++;
    for (i = prefix * 16; i < IOR_RING_FDS_BYTES; i++)
        clean &= got[i] == 0;
    for (i = 0; i < sizeof(ring.guard); i++)
        guard &= ring.guard[i] == 0xee;
    printf(" prefix=%%u clean=%%u guard=%%u reads=%%u maxread=%%u\n", prefix, clean, guard, reads, max_read);
}

static void run_stash(void) {
    unsigned present, id, emits;
    unsigned long long start, opcode_arg;
    scanf("%%u %%u %%llu %%u %%llu", &present, &id, &start, &emits, &opcode_arg);
    memset(&slot, 0, sizeof(slot));
    slot_present = present;
    slot.enter_trace_id = id;
    slot.start_ns = start;
    updates = 0;
    ior_stash_ring_fds(5, 9, 1000, emits, opcode_arg, 4242);
    printf("present=%%d id=%%u start=%%llu emit=%%u array=%%llu opcode=%%llu updates=%%u\n", slot_present,
           slot.enter_trace_id, slot.start_ns, slot.emit_event, slot.pending_filename, slot.pending_filename2, updates);
}

static void run_read(void) {
    long long ret;
    __u32 count = 0xeeeeeeee, status;
    scanf("%%u %%lld", &mapped, &ret);
    status = ior_read_ring_fds((__u64)user, ret, &count, ring.ev.updates);
    printf("status=%%u count=%%u", status, count);
    updates_report(ring.ev.updates);
}

static void run_emit(void) {
    unsigned long long opcode;
    long long ret;
    struct ring_fds_event *ev = &ring.ev;
    scanf("%%llu %%u %%lld %%u", &opcode, &mapped, &ret, &ring_full);
    ior_emit_ring_fds(7, 8, 9, 1234, opcode, (__u64)user, ret);
    printf("submitted=%%u drops=%%u", submitted, drops);
    if (submitted)
        printf(" event=%%u id=%%u time=%%llu pid=%%u tid=%%u opcode=%%u status=%%u count=%%u reserved=%%u",
               ev->event_type, ev->trace_id, ev->time, ev->pid, ev->tid, ev->opcode, ev->status, ev->count,
               ev->reserved);
    updates_report(ev->updates);
}

int main(void) {
    char op[8];
    while (scanf("%%7s", op) == 1) {
        memset(&ring, 0xee, sizeof(ring));
        fill_user();
        max_read = reads = drops = submitted = ring_full = 0;
        mapped = sizeof(user);
        if (!strcmp(op, "opcode")) {
            unsigned long long arg;
            scanf("%%llu", &arg);
            printf("opcode=%%u\n", ior_ring_fds_opcode(arg));
        } else if (!strcmp(op, "stash")) {
            run_stash();
        } else if (!strcmp(op, "read")) {
            run_read();
        } else {
            run_emit();
        }
        fflush(stdout);
    }
    return 0;
}
`

// ringFdsCase is one harness run: input is the line fed to the harness (see
// ringFdsHarnessTemplate), want the line it must print.
type ringFdsCase struct {
	name  string
	input string
	want  string
}

// ringFdsOpcodeCases cover ior_ring_fds_opcode: 20 and 21 are the two
// opcodes, with or without IORING_REGISTER_USE_REGISTERED_RING (bit 31) and
// whatever the upper half of the argument register holds.
var ringFdsOpcodeCases = []ringFdsCase{
	{"register", "opcode 20", "opcode=20"},
	{"unregister", "opcode 21", "opcode=21"},
	{"register with the registered-ring bit", "opcode 2147483668", "opcode=20"},
	{"unregister with the registered-ring bit", "opcode 2147483669", "opcode=21"},
	{"register with a dirty upper half", "opcode 4294967316", "opcode=20"},
	{"the opcode before", "opcode 19", "opcode=0"},
	{"the opcode after", "opcode 22", "opcode=0"},
	{"probe", "opcode 8", "opcode=0"},
	{"zero", "opcode 0", "opcode=0"},
	{"the registered-ring bit alone", "opcode 2147483648", "opcode=0"},
}

// ringFdsStashCases cover ior_stash_ring_fds, called as tid 5, trace ID 9,
// clock read 1000 and array pointer 4242. "present id start" describe the
// tid's enter-state entry before the call.
var ringFdsStashCases = []ringFdsCase{
	// Rate 1: the plain enter hook wrote no entry and the enter is emitted.
	{"rate 1 writes the entry", "stash 0 0 0 1 20",
		"present=1 id=9 start=1000 emit=1 array=4242 opcode=20 updates=1"},
	{"rate 1 unregister", "stash 0 0 0 1 2147483669",
		"present=1 id=9 start=1000 emit=1 array=4242 opcode=21 updates=1"},
	// Any other rate: the hook wrote this call's entry; the stash goes onto
	// it whether or not the enter is emitted, and writes no second one.
	{"sampled out, entry of this call", "stash 1 9 1000 0 20",
		"present=1 id=9 start=1000 emit=0 array=4242 opcode=20 updates=0"},
	{"sampled in, entry of this call", "stash 1 9 1000 1 21",
		"present=1 id=9 start=1000 emit=0 array=4242 opcode=21 updates=0"},
	// The hook could not write the entry and counted the call itself.
	{"no entry, not emitted", "stash 0 0 0 0 20",
		"present=0 id=0 start=0 emit=0 array=0 opcode=0 updates=0"},
	// Entries that are not this call's are not stashed onto.
	{"entry of an earlier call, emitted", "stash 1 9 900 1 20",
		"present=1 id=9 start=1000 emit=1 array=4242 opcode=20 updates=1"},
	{"entry of an earlier call, sampled out", "stash 1 9 900 0 20",
		"present=1 id=9 start=900 emit=0 array=0 opcode=0 updates=0"},
	{"entry of another syscall, emitted", "stash 1 3 1000 1 20",
		"present=1 id=9 start=1000 emit=1 array=4242 opcode=20 updates=1"},
	{"entry of another syscall, sampled out", "stash 1 3 1000 0 20",
		"present=1 id=3 start=1000 emit=0 array=0 opcode=0 updates=0"},
	// Every other opcode leaves the map alone.
	{"another opcode at rate 1", "stash 0 0 0 1 8",
		"present=0 id=0 start=0 emit=0 array=0 opcode=0 updates=0"},
	{"another opcode with an entry", "stash 1 9 1000 1 19",
		"present=1 id=9 start=1000 emit=0 array=0 opcode=0 updates=0"},
}

// ringFdsReadCases cover ior_read_ring_fds: "mapped ret". Statuses: 1 OK, 2
// READ_FAILED, 3 TOO_MANY. maxread is the largest read the helper asked for.
var ringFdsReadCases = []ringFdsCase{
	{"one entry", "read 4096 1", "status=1 count=1 prefix=1 clean=1 guard=1 reads=1 maxread=16"},
	{"three entries", "read 4096 3", "status=1 count=3 prefix=3 clean=1 guard=1 reads=1 maxread=48"},
	{"a full table", "read 4096 16", "status=1 count=16 prefix=16 clean=1 guard=1 reads=1 maxread=256"},
	// The caller's array ends right after its one element: a fixed 256-byte
	// read would fail as a whole.
	{"array ends with its entry", "read 16 1", "status=1 count=1 prefix=1 clean=1 guard=1 reads=1 maxread=16"},
	{"one entry too many", "read 4096 17", "status=3 count=0 prefix=0 clean=1 guard=1 reads=0 maxread=0"},
	{"a count beyond 32 bits", "read 4096 4294967297", "status=3 count=0 prefix=0 clean=1 guard=1 reads=0 maxread=0"},
	{"nothing registered", "read 4096 0", "status=3 count=0 prefix=0 clean=1 guard=1 reads=0 maxread=0"},
	{"array unreadable", "read 8 1", "status=2 count=0 prefix=0 clean=1 guard=1 reads=1 maxread=16"},
	{"second entry unreadable", "read 24 2", "status=2 count=0 prefix=0 clean=1 guard=1 reads=1 maxread=32"},
}

// ringFdsEmitCases cover ior_emit_ring_fds, called with pid 7, tid 8, enter
// trace ID 9 and clock read 1234: "opcode mapped ret ringfull". Event type 67
// is RING_FDS_EVENT.
var ringFdsEmitCases = []ringFdsCase{
	{"registration published", "emit 20 4096 2 0",
		"submitted=1 drops=0 event=67 id=9 time=1234 pid=7 tid=8 opcode=20 status=1 count=2 reserved=0" +
			" prefix=2 clean=1 guard=1 reads=1 maxread=32"},
	{"release published", "emit 21 4096 1 0",
		"submitted=1 drops=0 event=67 id=9 time=1234 pid=7 tid=8 opcode=21 status=1 count=1 reserved=0" +
			" prefix=1 clean=1 guard=1 reads=1 maxread=16"},
	// An unreadable array is reported, not dropped: userspace has to learn
	// that the table changed.
	{"unreadable array published as such", "emit 20 8 1 0",
		"submitted=1 drops=0 event=67 id=9 time=1234 pid=7 tid=8 opcode=20 status=2 count=0 reserved=0" +
			" prefix=0 clean=1 guard=1 reads=1 maxread=16"},
	{"another opcode publishes nothing", "emit 0 4096 1 0", "submitted=0 drops=0 prefix=0 clean=0 guard=1 reads=0 maxread=0"},
	{"nothing registered publishes nothing", "emit 20 4096 0 0", "submitted=0 drops=0 prefix=0 clean=0 guard=1 reads=0 maxread=0"},
	{"failed call publishes nothing", "emit 20 4096 -22 0", "submitted=0 drops=0 prefix=0 clean=0 guard=1 reads=0 maxread=0"},
	{"ring buffer full", "emit 20 4096 1 1", "submitted=0 drops=1 prefix=0 clean=0 guard=1 reads=0 maxread=0"},
}

// allRingFdsCases returns every case of the four helpers.
func allRingFdsCases() []ringFdsCase {
	var cases []ringFdsCase
	for _, group := range [][]ringFdsCase{ringFdsOpcodeCases, ringFdsStashCases, ringFdsReadCases, ringFdsEmitCases} {
		cases = append(cases, group...)
	}
	return cases
}

func TestRingFdsCapture(t *testing.T) {
	binary := compileRingFdsHarness(t, readRingFdsHelper(t))
	for name, got := range runRingFdsCases(t, binary, allRingFdsCases()) {
		if got != "" {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// ringFdsHelperMutation is one regression of iouring.c and a case that must
// fail.
type ringFdsHelperMutation struct {
	name, old, replacement, failingCase string
}

var ringFdsOpcodeMutations = []ringFdsHelperMutation{
	{"registered-ring bit not masked", " & ~IOR_REGISTER_USE_REGISTERED_RING;", ";",
		"register with the registered-ring bit"},
	{"upper half not dropped", "__u32 opcode = (__u32)opcode_arg & ~IOR_REGISTER_USE_REGISTERED_RING;",
		"__u64 opcode = opcode_arg & ~(__u64)IOR_REGISTER_USE_REGISTERED_RING;", "register with a dirty upper half"},
	{"release not captured", " || opcode == IOR_UNREGISTER_RING_FDS)", ")", "unregister"},
	{"registration not captured", "opcode == IOR_REGISTER_RING_FDS || ", "", "register"},
	{"every opcode captured", "        return opcode;\n    return 0;\n", "        return opcode;\n    return opcode;\n", "probe"},
}

var ringFdsStashMutations = []ringFdsHelperMutation{
	{"other opcodes write enter state", "    if (!opcode)\n        return;\n\n    state =", "    state =", "another opcode at rate 1"},
	{"stash onto an earlier call's entry", " && state->start_ns == now) {", ") {", "entry of an earlier call, sampled out"},
	{"stash onto another syscall's entry", "state && state->enter_trace_id == enter_trace_id && ", "state && ",
		"entry of another syscall, sampled out"},
	{"entry written for a counted call", "    if (!emits)\n        return;\n\n    fresh.start_ns", "    fresh.start_ns", "no entry, not emitted"},
	{"no entry written at rate 1", "    bpf_map_update_elem(&syscall_enter_state_map, &tid, &fresh, BPF_ANY);\n", "", "rate 1 writes the entry"},
	{"own entry written although the hook wrote one", "        state->pending_filename2 = opcode;\n        return;\n",
		"        state->pending_filename2 = opcode;\n", "sampled in, entry of this call"},
	{"fresh entry not marked emitted", "    fresh.emit_event = 1;\n", "", "rate 1 writes the entry"},
	{"fresh entry without its start time", "    fresh.start_ns = now;\n", "", "rate 1 writes the entry"},
	{"fresh entry without its syscall", "    fresh.enter_trace_id = enter_trace_id;\n", "", "rate 1 writes the entry"},
	{"pointer not stashed", "        state->pending_filename = arg;\n", "", "sampled out, entry of this call"},
	{"opcode not stashed", "        state->pending_filename2 = opcode;\n", "", "sampled out, entry of this call"},
	{"raw opcode argument stashed", "    fresh.pending_filename2 = opcode;\n", "    fresh.pending_filename2 = opcode_arg;\n", "rate 1 unregister"},
}

var ringFdsReadMutations = []ringFdsHelperMutation{
	{"count not bounded", "    if (ret > IOR_RING_FDS_MAX)\n        return RING_FDS_TOO_MANY;\n", "", "a count beyond 32 bits"},
	{"length not bounded", "    if (len == 0 || len > IOR_RING_FDS_BYTES)\n        return RING_FDS_TOO_MANY;\n", "", "nothing registered"},
	{"field not zero-filled", "    __builtin_memset(updates, 0, IOR_RING_FDS_BYTES);\n", "", "one entry"},
	{"fixed-size read", "bpf_probe_read_user(updates, len,", "bpf_probe_read_user(updates, IOR_RING_FDS_BYTES,", "array ends with its entry"},
	{"one element read whatever the count", "len = (__u32)ret * IOR_RING_FD_UPDATE_SIZE;", "len = IOR_RING_FD_UPDATE_SIZE;", "three entries"},
	{"failed read reported as entries",
		"    if (bpf_probe_read_user(updates, len, (void *)arg) < 0)\n        return RING_FDS_READ_FAILED;\n",
		"    bpf_probe_read_user(updates, len, (void *)arg);\n", "array unreadable"},
	{"count not reported", "    *count = (__u32)ret;\n", "", "one entry"},
	{"count left stale on failure", "    *count = 0;\n", "", "array unreadable"},
}

var ringFdsEmitMutations = []ringFdsHelperMutation{
	{"other opcodes published", "    if (!opcode || ret <= 0)\n", "    if (ret <= 0)\n", "another opcode publishes nothing"},
	{"failed call published", "    if (!opcode || ret <= 0)\n", "    if (!opcode)\n", "failed call publishes nothing"},
	{"call that registered nothing published", "    if (!opcode || ret <= 0)\n", "    if (!opcode || ret < 0)\n",
		"nothing registered publishes nothing"},
	{"record not stamped with the caller's clock read", "    ev->time = now;\n", "    ev->time = 0;\n", "registration published"},
	{"opcode not reported", "    ev->opcode = (__u32)opcode;\n", "", "release published"},
	{"status not reported", "    ev->status = ior_read_ring_fds(", "    ior_read_ring_fds(", "unreadable array published as such"},
	{"reserved word left stale", "    ev->reserved = 0;\n", "", "registration published"},
	{"unreadable array dropped", "    bpf_ringbuf_submit(ev, 0);\n",
		"    if (ev->status == RING_FDS_OK)\n        bpf_ringbuf_submit(ev, 0);\n", "unreadable array published as such"},
	{"full ring buffer not counted", "        ior_count_ringbuf_drop();\n", "", "ring buffer full"},
}

// TestRingFdsCaptureCatchesRegressions runs the cases against mutated
// helpers: each mutation must make its named case fail.
func TestRingFdsCaptureCatchesRegressions(t *testing.T) {
	helper := readRingFdsHelper(t)
	cases := allRingFdsCases()
	var mutations []ringFdsHelperMutation
	for _, group := range [][]ringFdsHelperMutation{ringFdsOpcodeMutations, ringFdsStashMutations,
		ringFdsReadMutations, ringFdsEmitMutations} {
		mutations = append(mutations, group...)
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			if strings.Count(helper, m.old) != 1 {
				t.Fatalf("iouring.c holds %d copies of %q, want 1", strings.Count(helper, m.old), m.old)
			}
			binary := compileRingFdsHarness(t, strings.Replace(helper, m.old, m.replacement, 1))
			result, known := runRingFdsCases(t, binary, cases)[m.failingCase]
			if !known {
				t.Fatalf("no case named %q", m.failingCase)
			}
			if result == "" {
				t.Fatalf("case %q still passes with the mutation", m.failingCase)
			}
		})
	}
}

func readRingFdsHelper(t *testing.T) string {
	t.Helper()
	helper, err := readRepoFile("internal", "c", "iouring.c")
	if err != nil {
		t.Fatalf("read iouring.c: %v", err)
	}
	return helper
}

// ringFdsTypeDefinitions cuts the ring-fds #defines and struct
// ring_fds_event out of types.h and struct syscall_enter_state out of
// maps.h, so the harness runs against the committed layouts and values.
func ringFdsTypeDefinitions(t *testing.T) (defines, record, state string) {
	t.Helper()
	typesH, err := readRepoFile("internal", "c", "types.h")
	if err != nil {
		t.Fatalf("read types.h: %v", err)
	}
	mapsH, err := readRepoFile("internal", "c", "maps.h")
	if err != nil {
		t.Fatalf("read maps.h: %v", err)
	}
	lines := regexp.MustCompile(`(?m)^#define (?:RING_FDS_[A-Z_]+|IOR_(?:UN)?REGISTER_RING_FDS|IOR_RING_FDS?_[A-Z_]+) .*$`).
		FindAllString(typesH, -1)
	record = regexp.MustCompile(`(?ms)^struct ring_fds_event \{\n.*?^\};\n`).FindString(typesH)
	state = regexp.MustCompile(`(?ms)^struct syscall_enter_state \{\n.*?^\};\n`).FindString(mapsH)
	if len(lines) != 9 || record == "" || state == "" {
		t.Fatalf("found %d ring-fds defines (want 9), record %q, enter state %q", len(lines), record, state)
	}
	return strings.Join(lines, "\n"), record, state
}

// compileRingFdsHarness builds the harness around helper (iouring.c,
// possibly mutated) with the host C compiler, skipping the test when none is
// installed. A crash of the helper must not take the test binary with it, so
// the harness is a separate program.
func compileRingFdsHarness(t *testing.T, helper string) string {
	t.Helper()
	defines, record, state := ringFdsTypeDefinitions(t)
	cc := hostCC(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "ringfds_harness.c")
	source := fmt.Sprintf(ringFdsHarnessTemplate, defines, record, state, helper)
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "ringfds_harness")
	args := []string{"-O1", "-Wall", "-Wno-unused-function", "-Wno-unused-result", "-o", binary, src}
	if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}

// runRingFdsCases feeds the cases to the harness, one run for all of them,
// and returns per case name what is wrong with its answer ("" when nothing
// is). A harness that crashes or stops early (a mutated helper may write out
// of bounds) fails every case it did not answer.
func runRingFdsCases(t *testing.T, binary string, cases []ringFdsCase) map[string]string {
	t.Helper()
	var input strings.Builder
	for _, c := range cases {
		input.WriteString(c.input + "\n")
	}
	cmd := exec.Command(binary)
	cmd.Stdin = strings.NewReader(input.String())
	out, runErr := cmd.Output()
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	results := make(map[string]string, len(cases))
	for i, c := range cases {
		switch {
		case i >= len(lines) || (runErr != nil && i == len(lines)-1):
			results[c.name] = fmt.Sprintf("harness gave no answer (run error: %v)", runErr)
		case lines[i] != c.want:
			results[c.name] = fmt.Sprintf("got  %q\nwant %q", lines[i], c.want)
		default:
			results[c.name] = ""
		}
	}
	return results
}
