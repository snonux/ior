package integrationtests

import "testing"

// TestIoctlBasic asserts that the ioctl-basic scenario deterministically fires
// the enter_ioctl tracepoint. ioctl is KindFd (fd@arg0); the fd resolves to the
// scenario's temp file, so we assert the path as well. Mirrors fcntl_test.go.
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
