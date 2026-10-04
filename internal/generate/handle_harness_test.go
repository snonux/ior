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

// The file-handle capture (internal/c/handle.c, task k03) reads a struct
// file_handle of caller-chosen length out of user memory. These tests compile
// the committed helper with the host C compiler against a simulated user
// buffer and ring buffer and run it, instead of pinning its source text: what
// matters is what lands in the record for a NULL pointer, an unreadable
// header, a handle that ends where the caller's mapping ends, and a
// handle_bytes beyond the field. Each property is also checked against a
// mutated helper, so the suite is shown to catch the regression it is for.

// handleHarnessTemplate wraps handle.c. The %s verbs take the handle #defines
// and struct file_handle_event from types.h and the helper source.
//
// User memory is the buffer user[], of which the first `mapped` bytes are
// readable: bpf_probe_read_user fails as a whole - zero-filling its
// destination, like the kernel helper - for a range that leaves them. Every
// destination is preset to 0xee, the stale bytes a ring-buffer reservation
// holds, and the handle field is followed by a guard the helper must not
// touch.
//
// Input lines are "read|emit null mapped bytes type full"; each prints one
// line (see the want strings of the cases), flushed at once so that a helper
// that crashes later still leaves the earlier answers.
const handleHarnessTemplate = `#include <stdio.h>
#include <string.h>

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
#define __always_inline inline __attribute__((always_inline))

%s
%s

static __u8 user[4096];
static unsigned mapped, max_read, drops, ring_full, submitted, discarded;
static int event_map;
static struct { struct file_handle_event ev; __u8 guard[64]; } ring;

static long bpf_probe_read_user(void *dst, unsigned int size, const void *src) {
    const __u8 *p = src;
    if (size > max_read)
        max_read = size;
    if (p < user || size > mapped || p + size > user + mapped) {
        if (size <= sizeof(ring))
            memset(dst, 0, size);
        return -14;
    }
    memcpy(dst, src, size);
    return 0;
}
static void *bpf_ringbuf_reserve(void *map, unsigned long size, unsigned long flags) {
    return ring_full ? 0 : &ring.ev;
}
static void bpf_ringbuf_submit(void *ev, unsigned long flags) { submitted++; }
static void bpf_ringbuf_discard(void *ev, unsigned long flags) { discarded++; }
static void ior_count_ringbuf_drop(void) { drops++; }
static __u64 stashed;
static void ior_stash_pending_filename2(__u32 tid, __u64 ptr) { stashed = ptr; }

%s

/* handle_report prints how many leading bytes are the caller's handle bytes
 * (1, 2, 3, ...), whether everything after them is zero, and the guard. */
static void handle_report(const __u8 *f_handle, unsigned want) {
    unsigned prefix = 0, i, clean = 1, guard = 1;
    while (prefix < IOR_MAX_HANDLE_SZ && prefix < want && f_handle[prefix] == (__u8)(prefix + 1))
        prefix++;
    for (i = prefix; i < IOR_MAX_HANDLE_SZ; i++)
        clean &= f_handle[i] == 0;
    for (i = 0; i < sizeof(ring.guard); i++)
        guard &= ring.guard[i] == 0xee;
    printf(" prefix=%%u clean=%%u guard=%%u maxread=%%u\n", prefix, clean, guard, max_read);
    fflush(stdout);
}

int main(void) {
    char op[8];
    unsigned null_ptr, bytes, i;
    int type;
    while (scanf("%%7s %%u %%u %%u %%d %%u", op, &null_ptr, &mapped, &bytes, &type, &ring_full) == 6) {
        struct file_handle_event *ev = &ring.ev;
        __u64 ptr = null_ptr ? 0 : (__u64)user;
        memset(&ring, 0xee, sizeof(ring));
        memset(user, 0, sizeof(user));
        memcpy(user, &bytes, 4);
        memcpy(user + 4, &type, 4);
        for (i = 0; i < 300; i++)
            user[8 + i] = (__u8)(i + 1);
        max_read = drops = submitted = discarded = 0;
        if (!strcmp(op, "read")) {
            __u32 status = ior_read_file_handle(ptr, &ev->handle_bytes, &ev->handle_type, ev->f_handle);
            printf("status=%%u bytes=%%u type=%%d", status, ev->handle_bytes, ev->handle_type);
        } else {
            ior_emit_file_handle(7, 8, 9, 1234, 1111, ptr);
            printf("submitted=%%u discarded=%%u drops=%%u", submitted, discarded, drops);
            if (submitted)
                printf(" event=%%u id=%%u time=%%llu enter=%%llu pid=%%u tid=%%u reserved=%%u status=%%u bytes=%%u type=%%d",
                       ev->event_type, ev->trace_id, ev->time, ev->enter_time, ev->pid, ev->tid, ev->reserved,
                       ev->handle_status, ev->handle_bytes, ev->handle_type);
        }
        handle_report(ev->f_handle, bytes);
    }
    ior_stash_pending_handle(1, 42);
    return stashed == 42 ? 0 : 1;
}
`

// handleCase is one harness run: op is "read" (ior_read_file_handle) or
// "emit" (ior_emit_file_handle); mapped is how many bytes of the caller's
// buffer are readable, bytes and handleType its header.
type handleCase struct {
	name       string
	op         string
	nullPtr    bool
	mapped     int
	bytes      uint32
	handleType int32
	ringFull   bool
	want       string
}

// handleReadCases cover ior_read_file_handle. Statuses: 1 OK, 2 NULL, 3
// READ_FAILED, 4 TOO_LARGE. maxread is the largest single read the helper
// asked for: 8 is the header alone.
var handleReadCases = []handleCase{
	{name: "null pointer", op: "read", nullPtr: true, mapped: 4096, bytes: 8, handleType: 1,
		want: "status=2 bytes=0 type=0 prefix=0 clean=1 guard=1 maxread=0"},
	{name: "unreadable header", op: "read", mapped: 4, bytes: 8, handleType: 1,
		want: "status=3 bytes=0 type=0 prefix=0 clean=1 guard=1 maxread=8"},
	{name: "empty handle", op: "read", mapped: 4096, bytes: 0, handleType: 5,
		want: "status=1 bytes=0 type=5 prefix=0 clean=1 guard=1 maxread=8"},
	{name: "ordinary handle", op: "read", mapped: 4096, bytes: 8, handleType: 1,
		want: "status=1 bytes=8 type=1 prefix=8 clean=1 guard=1 maxread=8"},
	// The caller's buffer ends right after its 8 handle bytes: a fixed
	// 128-byte read would fail as a whole.
	{name: "buffer ends with the handle", op: "read", mapped: 16, bytes: 8, handleType: -3,
		want: "status=1 bytes=8 type=-3 prefix=8 clean=1 guard=1 maxread=8"},
	{name: "largest handle", op: "read", mapped: 136, bytes: 128, handleType: 0x10001,
		want: "status=1 bytes=128 type=65537 prefix=128 clean=1 guard=1 maxread=128"},
	{name: "one byte too large", op: "read", mapped: 4096, bytes: 129, handleType: 1,
		want: "status=4 bytes=129 type=1 prefix=0 clean=1 guard=1 maxread=8"},
	{name: "absurd length", op: "read", mapped: 4096, bytes: 0xffffffff, handleType: 1,
		want: "status=4 bytes=4294967295 type=1 prefix=0 clean=1 guard=1 maxread=8"},
	{name: "handle bytes unreadable", op: "read", mapped: 20, bytes: 16, handleType: 1,
		want: "status=3 bytes=16 type=1 prefix=0 clean=1 guard=1 maxread=16"},
}

// handleEmitCases cover ior_emit_file_handle, called with pid 7, tid 8,
// enter trace ID 9, clock read 1234 and enter time 1111. Event type 65 is
// FILE_HANDLE_EVENT.
var handleEmitCases = []handleCase{
	{name: "handle published", op: "emit", mapped: 4096, bytes: 8, handleType: 1,
		want: "submitted=1 discarded=0 drops=0 event=65 id=9 time=1234 enter=1111 pid=7 tid=8 reserved=0 status=1 bytes=8 type=1" +
			" prefix=8 clean=1 guard=1 maxread=8"},
	{name: "null pointer reserves nothing", op: "emit", nullPtr: true, mapped: 4096, bytes: 8, handleType: 1,
		want: "submitted=0 discarded=0 drops=0 prefix=0 clean=0 guard=1 maxread=0"},
	{name: "ring buffer full", op: "emit", mapped: 4096, bytes: 8, handleType: 1, ringFull: true,
		want: "submitted=0 discarded=0 drops=1 prefix=0 clean=0 guard=1 maxread=0"},
	{name: "empty handle discarded", op: "emit", mapped: 4096, bytes: 0, handleType: 1,
		want: "submitted=0 discarded=1 drops=0 prefix=0 clean=1 guard=1 maxread=8"},
	{name: "unreadable handle discarded", op: "emit", mapped: 12, bytes: 8, handleType: 1,
		want: "submitted=0 discarded=1 drops=0 prefix=0 clean=1 guard=1 maxread=8"},
	{name: "oversized handle discarded", op: "emit", mapped: 4096, bytes: 200, handleType: 1,
		want: "submitted=0 discarded=1 drops=0 prefix=0 clean=1 guard=1 maxread=8"},
}

func TestFileHandleCapture(t *testing.T) {
	binary := compileHandleHarness(t, readHandleHelper(t))
	cases := append(append([]handleCase{}, handleReadCases...), handleEmitCases...)
	for name, got := range runHandleCases(t, binary, cases) {
		if got.err != "" {
			t.Errorf("%s: %s", name, got.err)
		}
	}
}

// handleMutation is one regression of handle.c and a case that must then
// fail.
type handleMutation struct {
	name, old, replacement, failingCase string
}

var handleMutations = []handleMutation{
	{"length not bounded", "    if (len > IOR_MAX_HANDLE_SZ)\n        return FILE_HANDLE_TOO_LARGE;\n", "",
		"one byte too large"},
	{"field not zero-filled", "    __builtin_memset(f_handle, 0, IOR_MAX_HANDLE_SZ);\n", "", "ordinary handle"},
	{"fixed-size read", "bpf_probe_read_user(f_handle, len,", "bpf_probe_read_user(f_handle, IOR_MAX_HANDLE_SZ,",
		"buffer ends with the handle"},
	{"bytes read from the header", "(void *)(handle_ptr + sizeof(head))", "(void *)handle_ptr", "ordinary handle"},
	{"failed byte read reported as a handle",
		"    if (bpf_probe_read_user(f_handle, len, (void *)(handle_ptr + sizeof(head))) < 0)\n        return FILE_HANDLE_READ_FAILED;\n",
		"    bpf_probe_read_user(f_handle, len, (void *)(handle_ptr + sizeof(head)));\n", "handle bytes unreadable"},
	{"type not reported", "    *handle_type = head.handle_type;\n", "", "ordinary handle"},
	{"empty handle published", " || ev->handle_bytes == 0) {", ") {", "empty handle discarded"},
	{"unreadable handle published", "ev->handle_status != FILE_HANDLE_OK || ", "", "unreadable handle discarded"},
	{"record not stamped with the caller's clock read", "    ev->time = now;\n", "    ev->time = 0;\n", "handle published"},
	{"record stamped with the exit time as its enter time", "    ev->enter_time = enter_ns;\n", "    ev->enter_time = now;\n",
		"handle published"},
	{"full ring buffer not counted", "        ior_count_ringbuf_drop();\n", "", "ring buffer full"},
}

// TestFileHandleCaptureCatchesRegressions runs the cases against mutated
// helpers: each mutation must make its named case fail.
func TestFileHandleCaptureCatchesRegressions(t *testing.T) {
	helper := readHandleHelper(t)
	cases := append(append([]handleCase{}, handleReadCases...), handleEmitCases...)
	for _, m := range handleMutations {
		t.Run(m.name, func(t *testing.T) {
			if strings.Count(helper, m.old) != 1 {
				t.Fatalf("handle.c holds %d copies of %q, want 1", strings.Count(helper, m.old), m.old)
			}
			binary := compileHandleHarness(t, strings.Replace(helper, m.old, m.replacement, 1))
			result, known := runHandleCases(t, binary, cases)[m.failingCase]
			if !known {
				t.Fatalf("no case named %q", m.failingCase)
			}
			if result.err == "" {
				t.Fatalf("case %q still passes with the mutation", m.failingCase)
			}
		})
	}
}

func readHandleHelper(t *testing.T) string {
	t.Helper()
	helper, err := readRepoFile("internal", "c", "handle.c")
	if err != nil {
		t.Fatalf("read handle.c: %v", err)
	}
	return helper
}

// handleTypeDefinitions cuts the handle #defines and struct
// file_handle_event out of types.h, so the harness runs against the committed
// layout and status values.
func handleTypeDefinitions(t *testing.T) (defines, record string) {
	t.Helper()
	typesH, err := readRepoFile("internal", "c", "types.h")
	if err != nil {
		t.Fatalf("read types.h: %v", err)
	}
	lines := regexp.MustCompile(`(?m)^#define (?:IOR_MAX_HANDLE_SZ|FILE_HANDLE_[A-Z_]+) .*$`).FindAllString(typesH, -1)
	record = regexp.MustCompile(`(?ms)^struct file_handle_event \{\n.*?^\};\n`).FindString(typesH)
	if len(lines) != 7 || record == "" {
		t.Fatalf("types.h: found %d handle defines (want 7) and record %q", len(lines), record)
	}
	return strings.Join(lines, "\n"), record
}

// compileHandleHarness builds the harness around helper (handle.c, possibly
// mutated) with the host C compiler, skipping the test when none is
// installed. A crash of the helper must not take the test binary with it, so
// the harness is a separate program.
func compileHandleHarness(t *testing.T, helper string) string {
	t.Helper()
	defines, record := handleTypeDefinitions(t)
	cc := hostCC(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "handle_harness.c")
	source := fmt.Sprintf(handleHarnessTemplate, defines, record, helper)
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "handle_harness")
	if out, err := exec.Command(cc, "-O1", "-Wall", "-Wno-unused-function", "-o", binary, src).CombinedOutput(); err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}

// handleResult is the outcome of one case: err is empty when the harness
// printed what the case wants.
type handleResult struct {
	err string
}

// runHandleCases feeds the cases to the harness, one run for all of them, and
// returns the outcome per case name. A harness that crashes or stops early (a
// mutated helper may write out of bounds) fails every case it did not answer.
func runHandleCases(t *testing.T, binary string, cases []handleCase) map[string]handleResult {
	t.Helper()
	var input strings.Builder
	for _, c := range cases {
		fmt.Fprintf(&input, "%s %d %d %d %d %d\n", c.op, boolInt(c.nullPtr), c.mapped, c.bytes, c.handleType, boolInt(c.ringFull))
	}
	cmd := exec.Command(binary)
	cmd.Stdin = strings.NewReader(input.String())
	out, runErr := cmd.Output()
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	results := make(map[string]handleResult, len(cases))
	for i, c := range cases {
		switch {
		case i >= len(lines) || (runErr != nil && i == len(lines)-1):
			results[c.name] = handleResult{err: fmt.Sprintf("harness gave no answer (run error: %v)", runErr)}
		case lines[i] != c.want:
			results[c.name] = handleResult{err: fmt.Sprintf("got  %q\nwant %q", lines[i], c.want)}
		default:
			results[c.name] = handleResult{}
		}
	}
	return results
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
