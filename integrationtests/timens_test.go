package integrationtests

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestCloseUntrackedInsideTimeNamespace is task y13 end to end: ior started
// inside a time namespace with a boottime offset (unshare -T --boottime N)
// labels the close rows of close-untracked exactly as it does outside one.
//
// The close row's rule compares a user-space CLOCK_BOOTTIME reading (when the
// procfs answer was read) with the BPF time of the close, and only the former
// is shifted by the namespace. Before the fix the two cases failed like this:
//
//   - ahead (+1000 s): every reading lay 1000 s after every record, so no
//     procfs answer ever counted as read before a close and the close of the
//     first file lost its name;
//   - behind (-1000 s): every reading lay before every record, so the answer
//     read after the close - the pipe that reused the number - was accepted.
//
// The workload stays in the host's time namespace; only ior is moved, which is
// also what puts the two clocks apart.
func TestCloseUntrackedInsideTimeNamespace(t *testing.T) {
	for name, offsetSec := range map[string]string{"ahead": "1000", "behind": "-1000"} {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness(t)
			h.IorWrapper = timeNamespaceWrapper(t, offsetSec)
			h.IorOutput = &OutputCapture{}
			path, pid, err := h.RunParquetWithIorArgs("close-untracked", defaultDuration, nil)
			if err != nil {
				t.Fatalf("run close-untracked in a time namespace: %v", err)
			}
			rows := readParquetRecords(t, path)
			assertParquetRowsOwnedBy(t, rows, uint32(pid), "ioworkload")
			assertCloseUntrackedRows(t, rows)
			if out := h.IorOutput.String(); strings.Contains(out, "time namespace") {
				t.Errorf("ior warned about a time namespace it can correct for:\n%s", out)
			}
		})
	}
}

// timeNamespaceWrapper returns the command prefix that starts a program in a
// new time namespace whose CLOCK_BOOTTIME is offsetSec seconds off the host's.
// unshare(1) execs the program itself (no --fork), and exec is what moves a
// task into the namespace it unshared, so the started process is ior, inside
// the namespace. The test is skipped where that cannot be set up: no
// unshare(1), no time namespaces (CONFIG_TIME_NS, Linux 5.6), or an offset the
// kernel refuses (a negative one larger than the uptime).
func timeNamespaceWrapper(t *testing.T, offsetSec string) []string {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("unshare(1) not found: %v", err)
	}
	wrapper := []string{unshare, "--time", "--boottime", offsetSec, "--"}
	probe := slices.Concat(wrapper[1:], []string{"true"})
	if out, err := exec.Command(unshare, probe...).CombinedOutput(); err != nil {
		t.Skipf("cannot enter a time namespace with boottime offset %s: %v: %s",
			offsetSec, err, strings.TrimSpace(string(out)))
	}
	return wrapper
}
