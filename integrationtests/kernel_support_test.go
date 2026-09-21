package integrationtests

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Kernel-support probes.
//
// The committed BPF artifact is generated on a recent mainline kernel, so the
// suite contains scenarios for syscalls an older host simply does not have
// (the *xattrat family, statmount/listmount/listns, open_tree_attr) and for
// features a host can switch off (io_uring via kernel.io_uring_disabled).
//
// Such a scenario must still RUN wherever the kernel supports it and may only
// be skipped where it provably cannot work. The probes below therefore ask the
// running kernel, never a version number: distribution kernels backport
// syscalls, so "5.14" says nothing about what is available. A skip always
// names the missing capability, so a run on a modern kernel that reports skips
// from this file is itself a finding.

// syscallTracefsRoots are the places tracefs is mounted. Newer systems mount
// it on /sys/kernel/tracing; older ones only expose it below debugfs.
var syscallTracefsRoots = []string{
	"/sys/kernel/tracing",
	"/sys/kernel/debug/tracing",
}

// syscallTracepointExists reports whether the running kernel exposes the
// sys_enter tracepoint of the named syscall under one of roots.
//
// The kernel creates syscalls/sys_enter_<name> for exactly the syscalls it was
// built with, so its presence is the precise answer to "can ior trace this
// syscall here, and can a workload call it without ENOSYS".
func syscallTracepointExists(roots []string, name string) bool {
	for _, root := range roots {
		path := filepath.Join(root, "events", "syscalls", "sys_enter_"+name)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// requireRootForProbe skips exactly like newTestHarness does. tracefs is
// readable by root only, so an unprivileged probe would mistake "permission
// denied" for "syscall missing"; the harness would skip the test a moment later
// anyway.
func requireRootForProbe(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF")
	}
}

// requireSyscalls skips the test unless the running kernel provides every
// named syscall. Use it for scenarios whose workload fails outright (ENOSYS)
// when a syscall is missing.
func requireSyscalls(t *testing.T, names ...string) {
	t.Helper()
	requireRootForProbe(t)
	for _, name := range names {
		if !syscallTracepointExists(syscallTracefsRoots, name) {
			t.Skipf("kernel does not provide the %s syscall (no syscalls/sys_enter_%s tracepoint)", name, name)
		}
	}
}

// kernelProvidesSyscall reports whether the running kernel provides the named
// syscall. Use it to make a single expectation conditional inside a scenario
// that otherwise runs fine, so the rest of the scenario is still asserted on
// an older kernel.
func kernelProvidesSyscall(t *testing.T, name string) bool {
	t.Helper()
	requireRootForProbe(t)
	return syscallTracepointExists(syscallTracefsRoots, name)
}

// expectWhereSupported returns exp when the kernel provides the named syscall
// and nil otherwise, logging the omission so it is visible in -v output.
func expectWhereSupported(t *testing.T, syscallName string, exp ExpectedEvent) []ExpectedEvent {
	t.Helper()
	if kernelProvidesSyscall(t, syscallName) {
		return []ExpectedEvent{exp}
	}
	t.Logf("kernel does not provide %s: its expectation is not asserted on this host", syscallName)
	return nil
}

// ioUringUnavailableReason classifies the errno of a probing io_uring_setup
// call. It returns a non-empty reason only when io_uring cannot be used at
// all; every other errno means the kernel accepted the call far enough to
// validate its arguments, i.e. io_uring works.
//
// io_uring_setup checks kernel.io_uring_disabled before anything else and
// answers EPERM (2 = disabled for everyone, 1 = disabled without
// CAP_SYS_ADMIN), so the probe's deliberately invalid arguments never get in
// the way: with io_uring allowed they yield EINVAL or EFAULT instead.
func ioUringUnavailableReason(errno syscall.Errno) string {
	switch {
	case errors.Is(errno, syscall.ENOSYS):
		return "kernel was built without io_uring (io_uring_setup: ENOSYS)"
	case errors.Is(errno, syscall.EPERM):
		return "io_uring is disabled on this host (io_uring_setup: EPERM; see sysctl kernel.io_uring_disabled)"
	default:
		return ""
	}
}

// requireIoUring skips the test unless this process may create an io_uring.
func requireIoUring(t *testing.T) {
	t.Helper()
	requireRootForProbe(t)
	// entries=0 with a NULL params pointer can never create a ring, so the
	// probe has no side effect to clean up.
	_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 0, 0, 0)
	if reason := ioUringUnavailableReason(errno); reason != "" {
		t.Skip(reason)
	}
}

func TestSyscallTracepointExists(t *testing.T) {
	root := t.TempDir()
	syscalls := filepath.Join(root, "events", "syscalls")
	if err := os.MkdirAll(filepath.Join(syscalls, "sys_enter_openat"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A plain file of the right name is not a tracepoint directory.
	if err := os.WriteFile(filepath.Join(syscalls, "sys_enter_listns"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missingRoot := filepath.Join(root, "not-mounted")

	tests := []struct {
		name    string
		roots   []string
		syscall string
		want    bool
	}{
		{name: "present", roots: []string{root}, syscall: "openat", want: true},
		{name: "absent", roots: []string{root}, syscall: "statmount", want: false},
		{name: "file is not a tracepoint", roots: []string{root}, syscall: "listns", want: false},
		{name: "falls back to a later root", roots: []string{missingRoot, root}, syscall: "openat", want: true},
		{name: "no tracefs at all", roots: []string{missingRoot}, syscall: "openat", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := syscallTracepointExists(tt.roots, tt.syscall); got != tt.want {
				t.Fatalf("syscallTracepointExists(%q) = %v, want %v", tt.syscall, got, tt.want)
			}
		})
	}
}

func TestIoUringUnavailableReason(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOSYS, syscall.EPERM} {
		if ioUringUnavailableReason(errno) == "" {
			t.Errorf("errno %v must mark io_uring unavailable", errno)
		}
	}
	// Argument-validation errors prove the kernel let the call through; 0 is
	// kept for completeness although the probe's arguments cannot succeed.
	for _, errno := range []syscall.Errno{syscall.EINVAL, syscall.EFAULT, syscall.ENOMEM, 0} {
		if reason := ioUringUnavailableReason(errno); reason != "" {
			t.Errorf("errno %v must not skip io_uring tests, got %q", errno, reason)
		}
	}
}

// TestKernelProbeFindsAnAlwaysPresentSyscall guards the probes themselves. If
// tracefs is mounted somewhere syscallTracefsRoots does not list, every probed
// test would skip and the run would look green while asserting nothing. openat
// exists on every kernel ior supports, so not finding it means the probe is
// blind, which must fail loudly rather than skip.
func TestKernelProbeFindsAnAlwaysPresentSyscall(t *testing.T) {
	requireRootForProbe(t)
	if !syscallTracepointExists(syscallTracefsRoots, "openat") {
		t.Fatalf("no syscalls/sys_enter_openat below any of %v: tracefs is not where the probes look, "+
			"so every kernel-support probe would skip its test", syscallTracefsRoots)
	}
}
