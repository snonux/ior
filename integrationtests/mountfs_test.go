package integrationtests

import "testing"

var mountfsTraceArgs = []string{
	"-trace-syscalls",
	"mount,umount,move_mount,fsopen,fsmount,pivot_root,quotactl,statmount,listmount,listns,swapon,swapoff",
}

func TestMountFsManagementSyscalls(t *testing.T) {
	runScenarioResultWithIorArgs(t, "mountfs-management", []ExpectedEvent{
		{Tracepoint: "enter_mount", MinCount: 1},
		{Tracepoint: "enter_umount", MinCount: 1},
		{Tracepoint: "enter_move_mount", MinCount: 1},
		{Tracepoint: "enter_fsopen", MinCount: 1},
		{Tracepoint: "enter_fsmount", MinCount: 1},
		{Tracepoint: "enter_pivot_root", MinCount: 1},
		{Tracepoint: "enter_quotactl", MinCount: 1},
		{Tracepoint: "enter_statmount", MinCount: 1},
		{Tracepoint: "enter_listmount", MinCount: 1},
		{Tracepoint: "enter_listns", MinCount: 1},
		{Tracepoint: "enter_swapon", MinCount: 1},
		{Tracepoint: "enter_swapoff", MinCount: 1},
	}, mountfsTraceArgs)
}
