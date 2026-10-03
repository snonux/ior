package generate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The name of a closed file (internal/c/fdname.c, task xz2) is read by
// hand-written BPF code that decides which of two records a close sends. As
// for the identity walk it shares (fileident_harness_test.go), these tests
// compile the committed helper with the host C compiler against a simulated
// task and ring buffer and run it: which files get the wide record, what the
// record holds, what the caller is told, and that the identity reaches the
// plain record's caller either way. Each property is also checked against a
// mutated helper.
//
// A host build cannot show that the verifier accepts the program or that the
// kernel's dentries look as simulated; the integration tests load the real
// object (TestCloseUntrackedClosesAreNamedByTheirLastComponent).

// fdNameHarnessTemplate wraps types.h, fileident.c and fdname.c (the three
// %s verbs). The table has 8 descriptors:
//
//	fd 0: /dir/foo.log, inode 100       fd 1: a pipe (own parent, ""), inode 42
//	fd 2: empty slot                    fd 3: a root directory "/", inode 3
//	fd 4: a 100-byte name, inode 4      fd 5: a file without a dentry, inode 5
//	fd 6: a 67-byte name, inode 6       fd 7: a dentry without a name, inode 7
//
// Input lines are "on kfunc full readfail fd"; each prints what the helper
// returned and stored, how the ring buffer was used and the record. The
// reservation is filled with 0x5a first, as real ring-buffer memory is not
// zeroed, and is followed by a canary. The read copies exactly the bytes it
// is asked for and leaves its destination alone when it fails (the kernel's
// zero-fills it, which the helper must not rely on: "String fields in
// ring-buffer records", internal/c/filter.c), so the terminator the record
// shows is the helper's own.
const fdNameHarnessTemplate = `#include <stdio.h>
#include <string.h>

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int __s32;
typedef long long __s64;
typedef unsigned long long __u64;
#define __always_inline inline __attribute__((always_inline))
#define __ksym
#define __weak

%s

struct inode { unsigned long i_ino; };
struct qstr { union { struct { u32 hash; u32 len; }; u64 hash_len; }; const unsigned char *name; };
struct dentry { struct dentry *d_parent; struct qstr d_name; };
struct path { struct dentry *dentry; };
struct file { struct inode *f_inode; struct path f_path; };
struct kiocb { struct file *ki_filp; };
struct fdtable { unsigned int max_fds; struct file **fd; };
struct files_struct { struct fdtable *fdt; };
struct task_struct { struct files_struct *files; };

static int have_kfunc, ring_full, read_fails, task_reads;
static int reserves, submits, discards, drops, reserved_size;
static __u32 IOR_FILE_IDENT;
static int event_map;
#define bpf_ksym_exists(sym) (have_kfunc)
#define bpf_core_type_id_kernel(type) (77)
#define bpf_core_field_offset(type, field) (0)

static struct task_struct task;
static struct task_struct *bpf_get_current_task_btf(void) {
    task_reads++;
    return &task;
}
void *bpf_rdonly_cast(const void *obj, __u32 id) { return (void *)obj; }

static struct { struct fd_name_event ev; char canary[8]; } ring;
static void *bpf_ringbuf_reserve(void *map, unsigned long size, int flags) {
    reserves++;
    reserved_size = (int)size;
    if (ring_full)
        return 0;
    memset(&ring.ev, 0x5a, sizeof(ring.ev));
    return &ring.ev;
}
static void bpf_ringbuf_submit(void *ev, int flags) { submits++; }
static void bpf_ringbuf_discard(void *ev, int flags) { discards++; }
static void ior_count_ringbuf_drop(void) { drops++; }
static long bpf_probe_read_kernel(void *dst, unsigned int size, const void *src) {
    if (read_fails || !src)
        return -14;
    memcpy(dst, src, size);
    return 0;
}

%s

%s

static char long_name[101], fit_name[68];
static struct inode inodes[8] = {{100}, {42}, {0}, {3}, {4}, {5}, {6}, {7}};
static struct dentry dir, dentries[8];
static struct file files[8];
static struct file *slots[8];
static struct fdtable fdt = {8, slots};
static struct files_struct fs = {&fdt};

static void name_dentry(int i, struct dentry *parent, const char *name) {
    dentries[i].d_parent = parent;
    dentries[i].d_name.name = (const unsigned char *)name;
    dentries[i].d_name.len = name ? strlen(name) : 9;
}

static void build_world(void) {
    int i;
    memset(long_name, 'L', 100);
    memset(fit_name, 'F', 67);
    dir.d_parent = &dir;
    for (i = 0; i < 8; i++) {
        files[i].f_inode = &inodes[i];
        files[i].f_path.dentry = &dentries[i];
        slots[i] = &files[i];
    }
    name_dentry(0, &dir, "foo.log");
    name_dentry(1, &dentries[1], "");
    name_dentry(3, &dentries[3], "/");
    name_dentry(4, &dir, long_name);
    name_dentry(6, &dir, fit_name);
    name_dentry(7, &dir, 0);
    slots[2] = 0;
    files[5].f_path.dentry = 0;
    task.files = &fs;
}

int main(void) {
    unsigned on;
    int fd;
    build_world();
    memcpy(ring.canary, "CANARY!", 8);
    while (scanf("%%u %%d %%d %%d %%d", &on, &have_kfunc, &ring_full, &read_fails, &fd) == 5) {
        __u32 ident = 999;
        int sent;
        IOR_FILE_IDENT = on;
        task_reads = reserves = submits = discards = drops = reserved_size = 0;
        memset(&ring.ev, 0, sizeof(ring.ev));
        sent = ior_emit_fd_name_enter(11, 12, 13, 1415, fd, &ident);
        printf("sent=%%d ident=%%u task=%%d reserve=%%d/%%d submit=%%d discard=%%d drop=%%d canary=%%s",
               sent, ident, task_reads, reserves, reserved_size, submits, discards, drops,
               memcmp(ring.canary, "CANARY!", 8) ? "broken" : "ok");
        if (submits) {
            ring.ev.name[sizeof(ring.ev.name) - 1] = 0;
            printf(" rec=%%u/%%u/%%llu/%%u/%%u/%%d/%%u len=%%u name=%%s", ring.ev.event_type, ring.ev.trace_id,
                   ring.ev.time, ring.ev.pid, ring.ev.tid, ring.ev.fd, ring.ev.file_ident, ring.ev.name_len,
                   ring.ev.name);
        }
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
`

// fdNameCase is one harness run. The zero value of the switches is a kernel
// that captures, a ring buffer with room and a readable name.
type fdNameCase struct {
	name      string
	off       bool // IOR_FILE_IDENT is 0
	noKfunc   bool // the kernel has no bpf_rdonly_cast
	full      bool // the ring buffer has no room
	readFails bool // the read of the name fails
	fd        int
	want      string
}

const (
	// fdNameSent is what a submitted wide record looks like from outside: one
	// walk, one reserve of 104 bytes, one submit.
	fdNameSent = " task=1 reserve=1/104 submit=1 discard=0 drop=0 canary=ok rec=66/13/1415/11/12/"
	// fdNamePlain is a walk that leaves the plain record to the caller.
	fdNamePlain = " task=1 reserve=0/0 submit=0 discard=0 drop=0 canary=ok"
	fdNameOff   = "sent=0 ident=0 task=0 reserve=0/0 submit=0 discard=0 drop=0 canary=ok"
)

// fdNameRecordCases are the closes that send the wide record.
var fdNameRecordCases = []fdNameCase{
	{name: "file below a directory", fd: 0, want: "sent=1 ident=100" + fdNameSent + "0/100 len=7 name=foo.log"},
	{name: "name longer than the record", fd: 4,
		want: "sent=1 ident=4" + fdNameSent + "4/4 len=100 name=" + strings.Repeat("L", 67)},
	{name: "name that just fits", fd: 6,
		want: "sent=1 ident=6" + fdNameSent + "6/6 len=67 name=" + strings.Repeat("F", 67)},
	{name: "dentry without a name", fd: 7, want: "sent=1 ident=7" + fdNameSent + "7/7 len=0 name="},
	{name: "name that cannot be read", fd: 0, readFails: true,
		want: "sent=1 ident=100" + fdNameSent + "0/100 len=0 name="},
	{name: "no room in the ring buffer", fd: 0, full: true,
		want: "sent=1 ident=100 task=1 reserve=1/104 submit=0 discard=0 drop=1 canary=ok"},
}

// fdNamePlainCases are the closes that keep the plain record, and what must
// keep the walk from starting.
var fdNamePlainCases = []fdNameCase{
	{name: "pipe", fd: 1, want: "sent=0 ident=42" + fdNamePlain},
	{name: "root directory", fd: 3, want: "sent=0 ident=3" + fdNamePlain},
	{name: "file without a dentry", fd: 5, want: "sent=0 ident=5" + fdNamePlain},
	{name: "empty slot", fd: 2, want: "sent=0 ident=0" + fdNamePlain},
	{name: "number past the table", fd: 8, want: "sent=0 ident=0" + fdNamePlain},
	{name: "negative number", fd: -1, want: "sent=0 ident=0" + fdNamePlain},
	{name: "capture switched off", off: true, fd: 0, want: fdNameOff},
	{name: "kernel without the kfunc", noKfunc: true, fd: 0, want: fdNameOff},
}

func fdNameCases() []fdNameCase {
	return append(append([]fdNameCase{}, fdNameRecordCases...), fdNamePlainCases...)
}

func TestFdNameCapture(t *testing.T) {
	binary := compileFdNameHarness(t, readFdNameHelper(t))
	for name, problem := range runFdNameCases(t, binary, fdNameCases()) {
		if problem != "" {
			t.Errorf("%s: %s", name, problem)
		}
	}
}

// fdNameMutation is one regression of fdname.c and a case that must then
// fail.
type fdNameMutation struct {
	name, old, replacement, failingCase string
}

// fdNameBound is the helper's cut of the copy length to the name field, and
// fdNameBoundComment the comment in front of it.
const (
	fdNameBound        = "    if (len > IOR_FD_NAME_LENGTH - 1)\n        len = IOR_FD_NAME_LENGTH - 1;\n"
	fdNameBoundComment = "    // The bound is what the verifier needs for a variable-length read into\n" +
		"    // the record, and it leaves room for the terminator.\n"
)

var fdNameMutations = []fdNameMutation{
	{"file without a directory named", "    if (dentry->d_parent == dentry)\n        return 0;\n", "", "pipe"},
	{"only a parentless file named", "dentry->d_parent == dentry", "dentry->d_parent != dentry", "file below a directory"},
	{"missing dentry dereferenced", "    if (!dentry)\n        return 0;\n    if (dentry->d_parent", "    if (dentry->d_parent",
		"file without a dentry"},
	{"off switch ignored", "!IOR_FILE_IDENT || ", "", "capture switched off"},
	{"missing kfunc ignored", "if (!IOR_FILE_IDENT || !ior_file_ident_supported())", "if (!IOR_FILE_IDENT)",
		"kernel without the kfunc"},
	{"identity not handed to the plain record", "        *file_ident = (__u32)inode->i_ino;\n", "", "pipe"},
	{"high word of the inode number", "*file_ident = (__u32)inode->i_ino;", "*file_ident = (__u32)(inode->i_ino >> 32);",
		"root directory"},
	{"identity left unset without a file", "    *file_ident = 0;\n", "", "empty slot"},
	{"record without the identity", "ev->file_ident = *file_ident;", "", "file below a directory"},
	{"record without the descriptor", "    ev->fd = fd;\n", "", "name longer than the record"},
	{"record sent as a plain fd_event", "ev->event_type = ENTER_FD_NAME_EVENT;", "ev->event_type = ENTER_FD_EVENT;",
		"file below a directory"},
	{"record without its time", "    ev->time = now;\n", "", "file below a directory"},
	{"plain record sent after a failed reserve", "        ior_count_ringbuf_drop();\n        return 1;",
		"        ior_count_ringbuf_drop();\n        return 0;", "no room in the ring buffer"},
	{"failed reserve not counted", "        ior_count_ringbuf_drop();\n", "", "no room in the ring buffer"},
	{"length kept for an unread name", "        ev->name_len = 0;\n", "", "name that cannot be read"},
	{"unread name terminated behind stale bytes", "        ev->name_len = 0;\n        len = 0;\n", "        ev->name_len = 0;\n",
		"name that cannot be read"},
	{"name left unterminated", "    ev->name[len] = '\\0';\n", "", "file below a directory"},
	{"cut length reported", "    ev->name_len = len;\n" + fdNameBoundComment + fdNameBound,
		fdNameBoundComment + fdNameBound + "    ev->name_len = len;\n", "name longer than the record"},
	{"name not cut to the field", fdNameBound, "", "name longer than the record"},
	{"name cut one byte late", fdNameBound,
		"    if (len > IOR_FD_NAME_LENGTH)\n        len = IOR_FD_NAME_LENGTH;\n", "name longer than the record"},
	{"name cut one byte early", fdNameBound,
		"    if (len > IOR_FD_NAME_LENGTH - 2)\n        len = IOR_FD_NAME_LENGTH - 2;\n", "name that just fits"},
}

// TestFdNameCaptureCatchesRegressions runs the cases against mutated helpers:
// each mutation must make its named case fail.
func TestFdNameCaptureCatchesRegressions(t *testing.T) {
	helper := readFdNameHelper(t)
	for _, m := range fdNameMutations {
		t.Run(m.name, func(t *testing.T) {
			if strings.Count(helper, m.old) != 1 {
				t.Fatalf("fdname.c holds %d copies of %q, want 1", strings.Count(helper, m.old), m.old)
			}
			binary := compileFdNameHarness(t, strings.Replace(helper, m.old, m.replacement, 1))
			problem, known := runFdNameCases(t, binary, fdNameCases())[m.failingCase]
			if !known {
				t.Fatalf("no case named %q", m.failingCase)
			}
			if problem == "" {
				t.Fatalf("case %q still passes with the mutation", m.failingCase)
			}
		})
	}
}

func readFdNameHelper(t *testing.T) string {
	t.Helper()
	helper, err := readRepoFile("internal", "c", "fdname.c")
	if err != nil {
		t.Fatalf("read fdname.c: %v", err)
	}
	return helper
}

// compileFdNameHarness builds the harness around the committed types.h and
// fileident.c and helper (fdname.c, possibly mutated) with the host C
// compiler, skipping the test when none is installed. -O0 for the reason
// compileFileIdentHarness gives.
func compileFdNameHarness(t *testing.T, helper string) string {
	t.Helper()
	cc := hostCC(t)
	typesH, err := readRepoFile("internal", "c", "types.h")
	if err != nil {
		t.Fatalf("read types.h: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "fdname_harness.c")
	source := fmt.Sprintf(fdNameHarnessTemplate, typesH, readFileIdentHelper(t), helper)
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "fdname_harness")
	if out, err := exec.Command(cc, "-O0", "-Wall", "-Wno-unused-function", "-o", binary, src).CombinedOutput(); err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}

// runFdNameCases feeds the cases to the harness, one run for all of them, and
// returns the problem per case name, empty when the harness printed what the
// case wants. A harness that crashes fails every case it did not answer.
func runFdNameCases(t *testing.T, binary string, cases []fdNameCase) map[string]string {
	t.Helper()
	var input strings.Builder
	for _, c := range cases {
		fmt.Fprintf(&input, "%d %d %d %d %d\n", boolInt(!c.off), boolInt(!c.noKfunc), boolInt(c.full), boolInt(c.readFails), c.fd)
	}
	cmd := exec.Command(binary)
	cmd.Stdin = strings.NewReader(input.String())
	out, runErr := cmd.Output()
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	problems := make(map[string]string, len(cases))
	for i, c := range cases {
		switch {
		case i >= len(lines) || lines[i] == "":
			problems[c.name] = fmt.Sprintf("harness gave no answer (run error: %v)", runErr)
		case lines[i] != c.want:
			problems[c.name] = fmt.Sprintf("got  %q\nwant %q", lines[i], c.want)
		default:
			problems[c.name] = ""
		}
	}
	return problems
}

// fdEnterFixture builds the enter tracepoint of a single-descriptor syscall
// whose descriptor is its first argument, as the kernel's format file gives
// it.
func fdEnterFixture(syscall string) GeneratedTracepoint {
	return GeneratedTracepoint{
		Format: &Format{
			Name:           "sys_enter_" + syscall,
			ExternalFields: []Field{{Name: "__syscall_nr"}, {Name: "fd"}},
		},
		Classification: ClassificationResult{Kind: KindFd},
	}
}

// TestGeneratorNamesTheFileOfACloseOnly pins the generator side of the
// capture, which the oracle only sees through the committed artifact: the
// committed close handler is the generator's complete output, the attempt
// and the local identity appear together and only for an fd_event enter of
// fdNameSyscalls, and the syscall list is the reviewed one.
func TestGeneratorNamesTheFileOfACloseOnly(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	closeEnter := fdEnterFixture("close")
	if got, want := handlerBody(t, artifact, "sys_enter_close"), strings.TrimSuffix(generateBPFHandler(closeEnter), "\n"); got != want {
		t.Fatalf("committed sys_enter_close differs from the generator output:\n%s", want)
	}
	if len(fdNameSyscalls) != len(namedFdSyscalls) || !emitsFdName("close") {
		t.Fatalf("fdNameSyscalls = %v, reviewed list is %v", fdNameSyscalls, namedFdSyscalls)
	}
	notNamed := map[string]GeneratedTracepoint{
		"another fd_event enter": fdEnterFixture("fsync"),
		"close's exit":           exitTracepoint("sys_exit_close", KindRet),
		"close of another kind": {Format: closeEnter.Format,
			Classification: ClassificationResult{Kind: KindFdSize}},
	}
	for name, tp := range notNamed {
		handler := generateBPFHandler(tp)
		if strings.Contains(handler, "ior_emit_fd_name_enter") || strings.Contains(handler, "= file_ident;") {
			t.Errorf("%s reports a file name or uses its local identity:\n%s", name, handler)
		}
	}
}
