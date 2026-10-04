package integrationtests

import (
	"syscall"
	"testing"
)

// TestIoctlBasic asserts that the ioctl-basic scenario deterministically fires
// the enter_ioctl tracepoint. ioctl is KindFcntl (fd@arg0, cmd@arg1, arg@arg2);
// the fd resolves to the scenario's temp file, so we assert the path as well.
// Mirrors fcntl_test.go.
func TestIoctlBasic(t *testing.T) {
	runScenario(t, "ioctl-basic", []ExpectedEvent{
		{
			PathContains: "ioctlfile.txt",
			Tracepoint:   "enter_ioctl",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

// TestIoctlCloexec proves end to end that the generated sys_enter_ioctl
// handler captures the ioctl cmd (task xo2): the scenario opens its file
// without O_CLOEXEC, issues FIOCLEX then writes, then FIONCLEX then writes.
// Only a tracer that sees the cmd reports O_CLOEXEC on the FIOCLEX ioctl row
// and on the first write, and drops it again for the second write.
func TestIoctlCloexec(t *testing.T) {
	const name = "ioctlcloexecfile.txt"
	rdwr := ptrTo(syscall.O_RDWR)
	runScenario(t, "ioctl-cloexec", []ExpectedEvent{
		{
			PathContains: name, Tracepoint: "enter_ioctl", Comm: "ioworkload", MinCount: 1,
			Flags: &ExpectedFlags{AccessMode: rdwr, Set: syscall.O_CLOEXEC},
		},
		{
			PathContains: name, Tracepoint: "enter_write", Comm: "ioworkload", MinCount: 1,
			Flags: &ExpectedFlags{AccessMode: rdwr, Set: syscall.O_CLOEXEC},
		},
		{
			PathContains: name, Tracepoint: "enter_write", Comm: "ioworkload", MinCount: 1,
			Flags: &ExpectedFlags{AccessMode: rdwr, Clear: syscall.O_CLOEXEC},
		},
	})
}
