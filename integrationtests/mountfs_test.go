package integrationtests

import "testing"

var mountfsTraceArgs = []string{
	"-trace-syscalls",
	"mount,umount,move_mount,fsopen,fsconfig,fspick,open_tree,mount_setattr,fsmount,pivot_root,quotactl,quotactl_fd,statmount,listmount,listns,swapon,swapoff",
}

func TestMountFsManagementSyscalls(t *testing.T) {
	runScenarioResultWithIorArgs(t, "mountfs-management", []ExpectedEvent{
		{Tracepoint: "enter_mount", MinCount: 1},
		{Tracepoint: "enter_umount", MinCount: 1},
		{Tracepoint: "enter_move_mount", MinCount: 1},
		{Tracepoint: "enter_fsopen", MinCount: 1},
		// fsconfig (KindFd), fspick (KindPathname), and open_tree (KindOpen) are
		// best-effort new-mount-API calls in the scenario. Their sys_enter_
		// tracepoints fire on kernel entry regardless of permission/validity, so
		// MinCount>=1 holds even when the syscalls themselves return an error.
		{Tracepoint: "enter_fsconfig", MinCount: 1},
		{Tracepoint: "enter_fspick", MinCount: 1},
		{Tracepoint: "enter_open_tree", MinCount: 1},
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
		{Tracepoint: "enter_statmount", MinCount: 1},
		{Tracepoint: "enter_listmount", MinCount: 1},
		{Tracepoint: "enter_listns", MinCount: 1},
		{Tracepoint: "enter_swapon", MinCount: 1},
		{Tracepoint: "enter_swapoff", MinCount: 1},
	}, mountfsTraceArgs)
}
