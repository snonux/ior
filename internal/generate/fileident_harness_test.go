package generate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The file identity capture (internal/c/fileident.c, task 603) walks kernel
// structures from the current task to an inode number. These tests compile
// the committed helper with the host C compiler against a simulated task and
// run it, instead of pinning its source text: what matters is the identity it
// returns for a descriptor in, at the edge of and outside the table, for an
// empty slot and a missing link of the chain, and that a run which switched
// the capture off, or a kernel that cannot run it, never starts the walk.
// Each property is also checked against a mutated helper, so the suite is
// shown to catch the regression it is for.
//
// What a host build cannot show is that the BPF verifier accepts the walk;
// the integration tests load the real object and compare its identities with
// stat(2) (integrationtests/fileident_test.go).

// fileIdentHarnessTemplate wraps fileident.c (the %s verb). The kernel types
// are cut down to the fields the walk reads. The simulated table has 8
// descriptors (max_fds) inside an array of 16 slots: slots 8..15 hold a file
// with inode 666, the answer of a walk that reads past the table, and the
// slot before the table one with inode 555.
//
//	fd 0: inode 100                 fd 1: inode 0x10000002a (low word 42)
//	fd 2: empty slot                fd 3: inode 7 (no inode in world noinode)
//	fd 4: inode 0x500000000 (low word 0)        fd 5..7: inode 55, 56, 57
//
// The three CO-RE questions are variables: have_kfunc (bpf_ksym_exists),
// kiocb_id (bpf_core_type_id_kernel) and slot_offset (bpf_core_field_offset).
// Input lines are "op on kfunc kiocbid slotoff world value"; each prints the
// identity, how often the walk cast a pointer and read the current task, and
// the type id it cast with, flushed at once so that a helper that crashes
// later still leaves the earlier answers.
const fileIdentHarnessTemplate = `#include <stdio.h>
#include <string.h>

typedef unsigned int __u32;
typedef int __s32;
typedef long long __s64;
typedef unsigned long long __u64;
#define __always_inline inline __attribute__((always_inline))
#define __ksym
#define __weak

struct inode { unsigned long i_ino; };
struct file { struct inode *f_inode; };
struct kiocb { struct file *ki_filp; };
struct fdtable { unsigned int max_fds; struct file **fd; };
struct files_struct { struct fdtable *fdt; };
struct task_struct { struct files_struct *files; };

static int have_kfunc, slot_offset, casts, task_reads;
static __u32 kiocb_id, cast_id, IOR_FILE_IDENT;
#define bpf_ksym_exists(sym) (have_kfunc)
#define bpf_core_type_id_kernel(type) (kiocb_id)
#define bpf_core_field_offset(type, field) (slot_offset)

static struct task_struct task;
static struct task_struct *bpf_get_current_task_btf(void) {
    task_reads++;
    return &task;
}

%s

void *bpf_rdonly_cast(const void *obj, __u32 id) {
    casts++;
    cast_id = id;
    return (void *)obj;
}

static struct inode inodes[8] = {{100}, {0x10000002aUL}, {0}, {7}, {0x500000000UL}, {55}, {56}, {57}};
static struct inode beyond = {666}, before = {555};
static struct file files[8], file_beyond = {&beyond}, file_before = {&before};
static struct file *slots[17];
static struct fdtable fdt;
static struct files_struct fs;

static void build_world(const char *world) {
    int i;
    slots[0] = &file_before;
    for (i = 0; i < 8; i++) {
        files[i].f_inode = &inodes[i];
        slots[1 + i] = &files[i];
    }
    for (i = 8; i < 16; i++)
        slots[1 + i] = &file_beyond;
    slots[1 + 2] = 0;
    fdt.max_fds = 8;
    fdt.fd = slots + 1;
    fs.fdt = &fdt;
    task.files = &fs;
    if (!strcmp(world, "nofiles"))
        task.files = 0;
    if (!strcmp(world, "nofdt"))
        fs.fdt = 0;
    if (!strcmp(world, "nofds"))
        fdt.fd = 0;
    if (!strcmp(world, "noinode"))
        files[3].f_inode = 0;
}

int main(void) {
    char op[8], world[16];
    long long value;
    unsigned on;
    while (scanf("%%7s %%u %%d %%u %%d %%15s %%lld", op, &on, &have_kfunc, &kiocb_id, &slot_offset, world, &value) == 7) {
        __u32 ident;
        IOR_FILE_IDENT = on;
        casts = task_reads = 0;
        cast_id = 0;
        build_world(world);
        if (!strcmp(op, "fd"))
            ident = ior_file_ident((__s32)value);
        else
            ident = ior_file_ident_of_ret(value);
        printf("ident=%%u casts=%%d task=%%d id=%%u\n", ident, casts, task_reads, cast_id);
        fflush(stdout);
    }
    return 0;
}
`

// fileIdentCase is one harness run. The zero value of the switches is the
// supported configuration: capture on, kfunc present, struct kiocb known as
// type 77 with ki_filp at offset 0.
type fileIdentCase struct {
	name       string
	ret        bool // ior_file_ident_of_ret instead of ior_file_ident
	off        bool // IOR_FILE_IDENT is 0
	noKfunc    bool // the kernel has no bpf_rdonly_cast
	noKiocb    bool // struct kiocb is not in the kernel's BTF
	slotOffset int  // offset of kiocb.ki_filp
	world      string
	value      int64
	want       string
}

const (
	fileIdentWalked  = " casts=1 task=1 id=77"
	fileIdentNoWalk  = "ident=0 casts=0 task=0 id=0"
	fileIdentNoTable = "ident=0 casts=0 task=1 id=0"
)

// fileIdentWalkCases cover the walk itself on a supported kernel.
var fileIdentWalkCases = []fileIdentCase{
	{name: "first descriptor", value: 0, want: "ident=100" + fileIdentWalked},
	{name: "last descriptor of the table", value: 7, want: "ident=57" + fileIdentWalked},
	{name: "inode number wider than the identity", value: 1, want: "ident=42" + fileIdentWalked},
	{name: "inode whose low word is zero", value: 4, want: "ident=0" + fileIdentWalked},
	{name: "empty slot", value: 2, want: "ident=0" + fileIdentWalked},
	{name: "file without an inode", world: "noinode", value: 3, want: "ident=0" + fileIdentWalked},
	{name: "number just past the table", value: 8, want: fileIdentNoTable},
	{name: "number far past the table", value: 15, want: fileIdentNoTable},
	{name: "negative number", value: -1, want: fileIdentNoTable},
	{name: "task without a table", world: "nofiles", value: 0, want: fileIdentNoTable},
	{name: "table without an fdtable", world: "nofdt", value: 0, want: fileIdentNoTable},
	{name: "fdtable without slots", world: "nofds", value: 0, want: fileIdentNoTable},
}

// fileIdentGateCases cover what must keep the walk from starting, and the
// return-value form.
var fileIdentGateCases = []fileIdentCase{
	{name: "capture switched off", off: true, value: 0, want: fileIdentNoWalk},
	{name: "kernel without the kfunc", noKfunc: true, value: 0, want: fileIdentNoWalk},
	{name: "kernel without struct kiocb", noKiocb: true, value: 0, want: fileIdentNoWalk},
	{name: "ki_filp moved off offset 0", slotOffset: 8, value: 0, want: fileIdentNoWalk},
	{name: "returned descriptor", ret: true, value: 5, want: "ident=55" + fileIdentWalked},
	{name: "failed call", ret: true, value: -9, want: fileIdentNoWalk},
	{name: "return value that is no descriptor", ret: true, value: 1 << 32, want: fileIdentNoWalk},
	{name: "largest descriptor number", ret: true, value: 0x7fffffff, want: fileIdentNoTable},
	{name: "returned descriptor with the capture off", ret: true, off: true, value: 5, want: fileIdentNoWalk},
}

func fileIdentCases() []fileIdentCase {
	return append(append([]fileIdentCase{}, fileIdentWalkCases...), fileIdentGateCases...)
}

func TestFileIdentCapture(t *testing.T) {
	binary := compileFileIdentHarness(t, readFileIdentHelper(t))
	for name, problem := range runFileIdentCases(t, binary, fileIdentCases()) {
		if problem != "" {
			t.Errorf("%s: %s", name, problem)
		}
	}
}

// fileIdentMutation is one regression of fileident.c and a case that must
// then fail.
type fileIdentMutation struct {
	name, old, replacement, failingCase string
}

var fileIdentMutations = []fileIdentMutation{
	{"table bound not checked", "    if (fd < 0 || (__u32)fd >= fdt->max_fds)\n        return 0;\n", "",
		"number just past the table"},
	{"table bound off by one", "(__u32)fd >= fdt->max_fds", "(__u32)fd > fdt->max_fds", "number just past the table"},
	{"negative number not refused", "    if (fd < 0 || (__u32)fd >= fdt->max_fds)", "    if (fd >= (__s32)fdt->max_fds)",
		"negative number"},
	{"empty slot dereferenced", "    if (!file)\n        return 0;\n", "", "empty slot"},
	{"missing table dereferenced", "    if (!files)\n        return 0;\n", "", "task without a table"},
	{"high word of the inode number", "(__u32)inode->i_ino", "(__u32)(inode->i_ino >> 32)",
		"inode number wider than the identity"},
	{"off switch ignored", "!IOR_FILE_IDENT || ", "", "capture switched off"},
	{"missing kfunc ignored", "if (!IOR_FILE_IDENT || !ior_file_ident_supported())", "if (!IOR_FILE_IDENT)",
		"kernel without the kfunc"},
	{"missing kiocb type ignored", " && bpf_core_type_id_kernel(struct kiocb) != 0", "", "kernel without struct kiocb"},
	{"moved slot member ignored", " &&\n           bpf_core_field_offset(struct kiocb, ki_filp) == 0", "",
		"ki_filp moved off offset 0"},
	{"slot cast to another type", "slot = bpf_rdonly_cast(fds + fd, bpf_core_type_id_kernel(struct kiocb));",
		"slot = bpf_rdonly_cast(fds + fd, 1);", "first descriptor"},
	{"wide return value truncated to a descriptor", "    if (ret < 0 || ret > 0x7fffffff)", "    if (ret < 0)",
		"return value that is no descriptor"},
}

// TestFileIdentCaptureCatchesRegressions runs the cases against mutated
// helpers: each mutation must make its named case fail.
func TestFileIdentCaptureCatchesRegressions(t *testing.T) {
	helper := readFileIdentHelper(t)
	for _, m := range fileIdentMutations {
		t.Run(m.name, func(t *testing.T) {
			if strings.Count(helper, m.old) != 1 {
				t.Fatalf("fileident.c holds %d copies of %q, want 1", strings.Count(helper, m.old), m.old)
			}
			binary := compileFileIdentHarness(t, strings.Replace(helper, m.old, m.replacement, 1))
			problem, known := runFileIdentCases(t, binary, fileIdentCases())[m.failingCase]
			if !known {
				t.Fatalf("no case named %q", m.failingCase)
			}
			if problem == "" {
				t.Fatalf("case %q still passes with the mutation", m.failingCase)
			}
		})
	}
}

func readFileIdentHelper(t *testing.T) string {
	t.Helper()
	helper, err := readRepoFile("internal", "c", "fileident.c")
	if err != nil {
		t.Fatalf("read fileident.c: %v", err)
	}
	return helper
}

// compileFileIdentHarness builds the harness around helper (fileident.c,
// possibly mutated) with the host C compiler, skipping the test when none is
// installed. A crash of the helper must not take the test binary with it, so
// the harness is a separate program.
func compileFileIdentHarness(t *testing.T, helper string) string {
	t.Helper()
	cc := hostCC(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "fileident_harness.c")
	if err := os.WriteFile(src, []byte(fmt.Sprintf(fileIdentHarnessTemplate, helper)), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "fileident_harness")
	// -O0: the mutations read through NULL and past the table on purpose, and
	// an optimiser is free to turn that into anything, including the right
	// answer.
	if out, err := exec.Command(cc, "-O0", "-Wall", "-Wno-unused-function", "-o", binary, src).CombinedOutput(); err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}

// runFileIdentCases feeds the cases to the harness, one run for all of them,
// and returns the problem per case name, empty when the harness printed what
// the case wants. A harness that crashes (a mutated helper may dereference
// NULL) fails every case it did not answer.
func runFileIdentCases(t *testing.T, binary string, cases []fileIdentCase) map[string]string {
	t.Helper()
	var input strings.Builder
	for _, c := range cases {
		fmt.Fprintln(&input, fileIdentInputLine(c))
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

// fileIdentInputLine renders one case as the harness reads it.
func fileIdentInputLine(c fileIdentCase) string {
	op, world, kiocbID := "fd", c.world, 77
	if c.ret {
		op = "ret"
	}
	if world == "" {
		world = "plain"
	}
	if c.noKiocb {
		kiocbID = 0
	}
	return fmt.Sprintf("%s %d %d %d %d %s %d", op, boolInt(!c.off), boolInt(!c.noKfunc), kiocbID, c.slotOffset, world, c.value)
}
