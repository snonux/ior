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
// the sched_process_exit context struct removed from vmlinux.h, i.e. what the
// build sees on an old-kernel host. The source tree is left untouched.
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
