package buildgate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// exitCtxStruct matches the vmlinux.h definition of the sched_process_exit
// tracepoint context. Kernels older than the group_dead change (RHEL/Rocky 8
// and 9) define that tracepoint from the shared sched_process_template, so a
// vmlinux.h dumped there has no such struct - and vmlinux.h is dumped from the
// BUILD host's kernel (Magefile.go), so the BPF source has to compile on it.
var exitCtxStruct = regexp.MustCompile(`(?ms)^struct trace_event_raw_sched_process_exit \{.*?^\};\n`)

// newtaskCtxStruct is the same for the task_newtask tracepoint context. Its
// vmlinux.h definition comes from the build host's kernel too, and the handler
// reads it through a local CO-RE flavor type, so the object must compile
// without it.
var newtaskCtxStruct = regexp.MustCompile(`(?ms)^struct trace_event_raw_task_newtask \{.*?^\};\n`)

// bpfBuildInputs locates the toolchain the BPF object build needs and skips
// the test when the host lacks it: clang, the libbpfgo-built libbpf headers
// and the (gitignored, per-host) vmlinux.h. Skipping mirrors `mage build`,
// which cannot run there either.
func bpfBuildInputs(t *testing.T) (clang, includeDir, srcDir string) {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("clang not installed: %v", err)
	}
	root := repoRoot(t)
	libbpfgo := os.Getenv("LIBBPFGO")
	if libbpfgo == "" {
		libbpfgo = filepath.Join(root, "..", "libbpfgo")
	}
	includeDir = filepath.Join(libbpfgo, "output")
	if _, err := os.Stat(filepath.Join(includeDir, "bpf", "bpf_helpers.h")); err != nil {
		t.Skipf("libbpf headers not built under %s: %v", includeDir, err)
	}
	srcDir = filepath.Join(root, "internal", "c")
	if _, err := os.Stat(filepath.Join(srcDir, "vmlinux.h")); err != nil {
		t.Skipf("no vmlinux.h (dump it with `mage generate`): %v", err)
	}
	return clang, includeDir, srcDir
}

// stagedOldKernelSources copies the BPF sources into a scratch directory with
// the sched_process_exit and task_newtask context structs removed from
// vmlinux.h, i.e. what the build sees on an old-kernel host. The source tree is left untouched.
func stagedOldKernelSources(t *testing.T, srcDir string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("read %s: %v", srcDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if e.Name() == "vmlinux.h" {
			data = exitCtxStruct.ReplaceAll(data, nil)
			if exitCtxStruct.Match(data) {
				t.Fatal("vmlinux.h still defines struct trace_event_raw_sched_process_exit after stripping")
			}
			data = newtaskCtxStruct.ReplaceAll(data, nil)
			if newtaskCtxStruct.Match(data) {
				t.Fatal("vmlinux.h still defines struct trace_event_raw_task_newtask after stripping")
			}
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", e.Name(), err)
		}
	}
	return dst
}

// compileBPF runs clang with the flags of Magefile.go's buildBPFObject and
// returns its combined output and error.
func compileBPF(clang, includeDir, src, obj string) ([]byte, error) {
	cmd := exec.Command(clang, "-g", "-O2", "-Wall", "-fpie", "-target", "bpf",
		"-D__TARGET_ARCH_amd64", "-I"+includeDir, "-c", src, "-o", obj)
	return cmd.CombinedOutput()
}

// TestBPFObjectCompilesWithoutSchedProcessExitStruct is the regression test for
// the Rocky 8/9 build failure: exec.c named struct
// trace_event_raw_sched_process_exit directly, so a vmlinux.h without it
// ("incomplete definition of type") broke the whole object. The fix reads
// group_dead through a local CO-RE flavor type instead.
func TestBPFObjectCompilesWithoutSchedProcessExitStruct(t *testing.T) {
	clang, includeDir, srcDir := bpfBuildInputs(t)
	staged := stagedOldKernelSources(t, srcDir)

	// Control: the stripped vmlinux.h really does reproduce the reported
	// failure for code that names the struct. Without this, a regex that
	// silently stopped matching would leave the real check below vacuous.
	probe := filepath.Join(staged, "probe.bpf.c")
	probeSrc := "#include \"vmlinux.h\"\n" +
		"int probe(struct trace_event_raw_sched_process_exit *c) { return c->group_dead; }\n"
	if err := os.WriteFile(probe, []byte(probeSrc), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	out, err := compileBPF(clang, includeDir, probe, filepath.Join(staged, "probe.o"))
	if err == nil {
		t.Fatal("control compile succeeded although vmlinux.h lost the struct; the stripping is not effective")
	}
	if !bytes.Contains(out, []byte("trace_event_raw_sched_process_exit")) {
		t.Fatalf("control compile failed for an unrelated reason:\n%s", out)
	}

	obj := filepath.Join(staged, "ior.bpf.o")
	out, err = compileBPF(clang, includeDir, filepath.Join(staged, "ior.bpf.c"), obj)
	if err != nil {
		t.Fatalf("ior.bpf.c does not compile against a vmlinux.h lacking struct "+
			"trace_event_raw_sched_process_exit (RHEL/Rocky 8 and 9 hosts): %v\n%s", err, out)
	}

	// The field access must still be a CO-RE relocation against the kernel
	// type: the flavor's name survives in the object's BTF. If it were gone,
	// group_dead would be read at a compile-time offset and be wrong on
	// kernels whose tracepoint layout differs from the build host's.
	data, err := os.ReadFile(obj)
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if !bytes.Contains(data, []byte("trace_event_raw_sched_process_exit___ior")) {
		t.Fatal("object carries no trace_event_raw_sched_process_exit___ior CO-RE flavor type")
	}
}

// TestBPFObjectCompilesAgainstHostVmlinux guards the other direction: on the
// new-kernel host the plain vmlinux.h (struct present) must keep compiling,
// so the flavor type cannot conflict with the kernel definition.
func TestBPFObjectCompilesAgainstHostVmlinux(t *testing.T) {
	clang, includeDir, srcDir := bpfBuildInputs(t)
	obj := filepath.Join(t.TempDir(), "ior.bpf.o")
	if out, err := compileBPF(clang, includeDir, filepath.Join(srcDir, "ior.bpf.c"), obj); err != nil {
		t.Fatalf("ior.bpf.c does not compile against the host vmlinux.h: %v\n%s", err, out)
	}
}

// TestBPFObjectCompilesWithoutTaskNewtaskStruct is the same guard for the
// task_newtask handler (task fr2): it must not name the vmlinux.h context
// struct, whose presence and layout depend on the build host's kernel. The
// handler reads pid and clone_flags through a local CO-RE flavor type instead.
func TestBPFObjectCompilesWithoutTaskNewtaskStruct(t *testing.T) {
	clang, includeDir, srcDir := bpfBuildInputs(t)
	staged := stagedOldKernelSources(t, srcDir)

	// Control, as for sched_process_exit: the stripped header must really
	// reject code naming the struct, or the object build below proves nothing.
	probe := filepath.Join(staged, "probe.bpf.c")
	probeSrc := "#include \"vmlinux.h\"\n" +
		"int probe(struct trace_event_raw_task_newtask *c) { return c->pid; }\n"
	if err := os.WriteFile(probe, []byte(probeSrc), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	out, err := compileBPF(clang, includeDir, probe, filepath.Join(staged, "probe.o"))
	if err == nil {
		t.Fatal("control compile succeeded although vmlinux.h lost the struct; the stripping is not effective")
	}
	if !bytes.Contains(out, []byte("trace_event_raw_task_newtask")) {
		t.Fatalf("control compile failed for an unrelated reason:\n%s", out)
	}

	obj := filepath.Join(staged, "ior.bpf.o")
	out, err = compileBPF(clang, includeDir, filepath.Join(staged, "ior.bpf.c"), obj)
	if err != nil {
		t.Fatalf("ior.bpf.c does not compile against a vmlinux.h lacking struct "+
			"trace_event_raw_task_newtask: %v\n%s", err, out)
	}
	data, err := os.ReadFile(obj)
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if !bytes.Contains(data, []byte("trace_event_raw_task_newtask___ior")) {
		t.Fatal("object carries no trace_event_raw_task_newtask___ior CO-RE flavor type")
	}
}

// ctxScalarLoad matches a load straight from the program's context register:
// the only shape of context access the verifiers of RHEL/Rocky 8 and 9
// (4.18, 5.14) accept once CO-RE has patched the offset.
var ctxScalarLoad = regexp.MustCompile(`= \*\(u(8|16|32|64) \*\)\(r1 \+ 0x[0-9a-f]+\)`)

// TestTaskNewtaskHandlerHasNoContextPointerArithmetic pins the verifier-facing
// property of the compiled handler. Copying the tracepoint's char comm[16]
// out of the context compiled to `r1 = <CO-RE offset>; r2 = ctx; r2 += r1;
// *(u32 *)(r2 + 4)`, which old verifiers reject as "dereference of modified
// ctx ptr" - and one rejected program fails the load of the whole object, so
// ior would not start. Every CO-RE-relocated instruction of the handler must
// therefore be a plain fixed-offset load from r1 (the context register at
// entry); anything else means context arithmetic crept back in.
//
// It inspects the object with llvm-objdump and skips when that is missing. The
// check has teeth: TestCtxScalarLoadPatternRejectsPointerArithmetic feeds the
// pattern the shape of the bad code.
func TestTaskNewtaskHandlerHasNoContextPointerArithmetic(t *testing.T) {
	objdump, err := exec.LookPath("llvm-objdump")
	if err != nil {
		t.Skipf("llvm-objdump not installed: %v", err)
	}
	clang, includeDir, srcDir := bpfBuildInputs(t)
	obj := filepath.Join(t.TempDir(), "ior.bpf.o")
	if out, err := compileBPF(clang, includeDir, filepath.Join(srcDir, "ior.bpf.c"), obj); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	out, err := exec.Command(objdump, "-dr", "--no-show-raw-insn",
		"--section=tracepoint/task/task_newtask", obj).CombinedOutput()
	if err != nil {
		t.Fatalf("llvm-objdump: %v\n%s", err, out)
	}
	relocated := coreRelocatedInstructions(string(out))
	if len(relocated) < 2 {
		t.Fatalf("found %d CO-RE relocated instructions in handle_task_newtask, want at least the pid and "+
			"clone_flags loads; the disassembly parser or the section name is broken:\n%s", len(relocated), out)
	}
	for _, insn := range relocated {
		if !ctxScalarLoad.MatchString(insn) {
			t.Errorf("CO-RE relocated instruction %q is not a fixed-offset load from the context register", insn)
		}
	}
}

// TestTaskRenameHandlerReadsItsArgumentsWithoutCoreRelocation pins the
// verifier-facing property of the raw-tracepoint handler (task lr2): its
// context is the tracepoint's TP_PROTO arguments, read as plain u64 loads at
// fixed offsets 0 and 8. Going through vmlinux.h's struct
// bpf_raw_tracepoint_args::args instead compiles to a CO-RE-relocated offset
// added to the context register, i.e. context pointer arithmetic, which is the
// shape old verifiers reject (see TestTaskNewtaskHandlerHasNoContextPointerArithmetic).
// The only relocations the handler may carry are the task_struct offsets it
// probe-reads from kernel memory.
func TestTaskRenameHandlerReadsItsArgumentsWithoutCoreRelocation(t *testing.T) {
	objdump, err := exec.LookPath("llvm-objdump")
	if err != nil {
		t.Skipf("llvm-objdump not installed: %v", err)
	}
	clang, includeDir, srcDir := bpfBuildInputs(t)
	obj := filepath.Join(t.TempDir(), "ior.bpf.o")
	if out, err := compileBPF(clang, includeDir, filepath.Join(srcDir, "ior.bpf.c"), obj); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	out, err := exec.Command(objdump, "-dr", "--no-show-raw-insn",
		"--section=raw_tracepoint/task_rename", obj).CombinedOutput()
	if err != nil {
		t.Fatalf("llvm-objdump: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("struct task_struct::tgid")) || !bytes.Contains(out, []byte("struct task_struct::pid")) {
		t.Fatalf("handle_task_rename carries no task_struct pid/tgid relocations; the disassembly parser or the "+
			"section name is broken:\n%s", out)
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if bytes.Contains(line, []byte("CO-RE")) && bytes.Contains(line, []byte("bpf_raw_tracepoint_args")) {
			t.Errorf("handle_task_rename relocates its context access: %q", line)
		}
	}
	if !regexp.MustCompile(`= \*\(u64 \*\)\(r\d \+ 0x0\)`).Match(out) ||
		!regexp.MustCompile(`= \*\(u64 \*\)\(r\d \+ 0x8\)`).Match(out) {
		t.Errorf("handle_task_rename does not load both tracepoint arguments at offsets 0 and 8:\n%s", out)
	}
}

// coreRelocatedInstructions returns, from llvm-objdump -dr output, the
// instruction line that precedes each CO-RE relocation line.
func coreRelocatedInstructions(dump string) []string {
	var insns []string
	prev := ""
	for _, line := range bytes.Split([]byte(dump), []byte("\n")) {
		text := string(line)
		if bytes.Contains(line, []byte("CO-RE")) {
			insns = append(insns, prev)
			continue
		}
		prev = text
	}
	return insns
}

// TestCtxScalarLoadPatternRejectsPointerArithmetic keeps the check above
// honest against the shape it exists to catch.
func TestCtxScalarLoadPatternRejectsPointerArithmetic(t *testing.T) {
	good := "       1:\tw9 = *(u32 *)(r1 + 0x8)"
	bad := []string{
		"      51:\tr1 = 0xc",
		"      54:\tw1 = *(u32 *)(r2 + 0x4)",
		"      55:\tw3 = *(u32 *)(r6 + 0xc)",
	}
	if !ctxScalarLoad.MatchString(good) {
		t.Errorf("pattern rejects a plain context load %q", good)
	}
	for _, line := range bad {
		if ctxScalarLoad.MatchString(line) {
			t.Errorf("pattern accepts %q", line)
		}
	}
}
