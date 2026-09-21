package integrationtests

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

var mountfsTraceArgs = []string{
	"-trace-syscalls",
	"mount,umount,move_mount,fsopen,fsconfig,fspick,open_tree,open_tree_attr,mount_setattr,fsmount,pivot_root,quotactl,quotactl_fd,statmount,listmount,listns,swapon,swapoff,close",
}

func TestMountFsManagementSyscalls(t *testing.T) {
	openTreeFlags := &ExpectedFlags{
		AccessMode: ptrTo(syscall.O_RDONLY),
		Set:        unix.O_PATH | syscall.O_CLOEXEC,
		Clear:      syscall.O_WRONLY | syscall.O_NOCTTY | syscall.O_NONBLOCK,
	}
	expected := []ExpectedEvent{
		{Tracepoint: "enter_mount", MinCount: 1},
		{Tracepoint: "enter_umount", MinCount: 1},
		{Tracepoint: "enter_move_mount", PathContains: "move-mount-destination", MinCount: 1},
		{Tracepoint: "enter_fsopen", PathContains: "fsopen:tmpfs", MinCount: 1},
		// fsconfig (KindFd), fspick (KindPathname), and the open_tree family are
		// best-effort new-mount-API calls in the scenario. Their sys_enter_
		// tracepoints fire on kernel entry regardless of permission/validity, so
		// MinCount>=1 holds even when the syscalls themselves return an error.
		{Tracepoint: "enter_fsconfig", MinCount: 1},
		{PathContains: "/", Tracepoint: "enter_fspick", MinCount: 1},
		{
			PathContains: "open-tree-target",
			Tracepoint:   "enter_open_tree",
			MinCount:     1,
			Flags:        openTreeFlags,
		},
		{
			PathContains: "open-tree-target",
			Tracepoint:   "enter_close",
			MinCount:     1,
			Flags:        openTreeFlags,
		},
		// mount_setattr (KindPathname, path@arg1) changes per-mount attributes
		// of an existing mount and needs CAP_SYS_ADMIN (Linux 5.12+), so it
		// returns EPERM/EINVAL in the scenario. Its sys_enter_ tracepoint fires
		// on kernel entry regardless of permission/validity, so MinCount>=1
		// holds even though the call itself fails.
		{Tracepoint: "enter_mount_setattr", MinCount: 1},
		{Tracepoint: "enter_fsmount", MinCount: 1},
		{Tracepoint: "enter_pivot_root", MinCount: 1},
		{Tracepoint: "enter_quotactl", MinCount: 1},
		// quotactl_fd (KindFd, fd@arg0) is the fd-based sibling of quotactl,
		// issued best-effort on an fd opened on the mount point. Its sys_enter_
		// tracepoint fires on kernel entry regardless of privilege/quota support.
		{Tracepoint: "enter_quotactl_fd", MinCount: 1},
		{Tracepoint: "enter_swapon", MinCount: 1},
		{Tracepoint: "enter_swapoff", MinCount: 1},
	}
	// These four are newer than the rest of the scenario (open_tree_attr 6.15,
	// statmount/listmount 6.8, listns 6.19). The workload issues them
	// best-effort, so on a kernel without them the scenario still runs and
	// everything above is still asserted; only their own expectation is
	// dropped. On a kernel that provides them they are asserted as before.
	for _, name := range []string{"open_tree_attr", "statmount", "listmount", "listns"} {
		expected = append(expected, expectWhereSupported(t, name,
			ExpectedEvent{Tracepoint: "enter_" + name, MinCount: 1})...)
	}
	runScenarioResultWithIorArgs(t, "mountfs-management", expected, mountfsTraceArgs)
}
