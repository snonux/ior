package integrationtests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
			// Not vacuous: the same capture sees the warning when ior has
			// one (TestUnknownTimeNamespaceOffsetIsWarnedAboutOnce).
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
// unshare(1), no time namespaces (CONFIG_TIME_NS, Linux 5.6), an offset the
// kernel refuses (a negative one larger than the uptime), or a kernel on which
// exec does not move the task (programInsideNewTimeNamespace).
func timeNamespaceWrapper(t *testing.T, offsetSec string) []string {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("unshare(1) not found: %v", err)
	}
	wrapper := []string{unshare, "--time", "--boottime", offsetSec, "--"}
	if err := programInsideNewTimeNamespace(wrapper); err != nil {
		t.Skipf("cannot start a program inside a time namespace with boottime offset %s: %v",
			offsetSec, err)
	}
	return wrapper
}

// programInsideNewTimeNamespace reports, as an error, why a program started
// through wrapper would not run inside the namespace the wrapper created. It
// starts readlink(1) the way the harness starts ior and has it print its own
// two time namespace links. They differ when the exec'd program was left in
// the old namespace while only its children would enter the new one, which is
// what kernels that do not switch on exec do (reported for those before about
// 6.1; not seen here, Linux 7.2 switches). ior then rightly reports an unknown
// offset, so the test's premise - ior inside the namespace - does not hold and
// it is skipped rather than failed.
func programInsideNewTimeNamespace(wrapper []string) error {
	probe := slices.Concat(wrapper[1:],
		[]string{"readlink", "/proc/self/ns/time", "/proc/self/ns/time_for_children"})
	out, err := exec.Command(wrapper[0], probe...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	links := strings.Fields(string(out))
	if len(links) != 2 {
		return fmt.Errorf("readlink printed %q, want the two time namespace links", out)
	}
	if links[0] != links[1] {
		return fmt.Errorf("the exec'd program stays in %s, only its children enter %s",
			links[0], links[1])
	}
	return nil
}

// TestUnknownTimeNamespaceOffsetIsWarnedAboutOnce is the other half of task
// y13: when ior cannot tell its boottime offset it must say so, once, where a
// headless user sees it. The first version collected the warning after the
// setup warnings had been handed to the event loop and never printed it.
//
// The offset is made unknown by giving ior a timens_offsets file no kernel
// prints. The run itself stays in the host's time namespace, so the assumed
// offset 0 is the true one and the close rows are right all the same.
//
// It is also what gives the "no warning" check of
// TestCloseUntrackedInsideTimeNamespace its meaning: the same capture, on the
// same kind of run, does see the warning when there is one.
func TestUnknownTimeNamespaceOffsetIsWarnedAboutOnce(t *testing.T) {
	h := newTestHarness(t)
	h.IorWrapper = garbledTimensOffsetsWrapper(t)
	h.IorOutput = &OutputCapture{}
	path, pid, err := h.RunParquetWithIorArgs("close-untracked", defaultDuration, nil)
	if err != nil {
		t.Fatalf("run close-untracked with a garbled timens_offsets: %v", err)
	}
	rows := readParquetRecords(t, path)
	assertParquetRowsOwnedBy(t, rows, uint32(pid), "ioworkload")
	assertCloseUntrackedRows(t, rows)
	out := h.IorOutput.String()
	if n := strings.Count(out, unknownBootClockWarning); n != 1 {
		t.Errorf("ior printed the unknown-offset warning %d times, want once:\n%s", n, out)
	}
	if !strings.Contains(out, "boottime seconds") {
		t.Errorf("the warning does not say what is wrong with the file:\n%s", out)
	}
}

const (
	// unknownBootClockWarning is the start of ior's warning about an offset
	// it could not determine (internal/bootclock.go).
	unknownBootClockWarning = "Could not determine the boottime offset of ior's time namespace"
	// garbledTimensOffsets has a boottime line whose numbers are none.
	garbledTimensOffsets = "monotonic 0 0\nboottime x y\n"
)

// garbledTimensOffsetsWrapper returns a command prefix that starts a program
// which reads garbledTimensOffsets as its /proc/self/timens_offsets. A shell
// in a private mount namespace (unshare -m: nothing outside sees the mount,
// and it is gone with the process) bind-mounts the file over its own
// /proc/<pid>/timens_offsets and then execs the program, which keeps the pid
// and so the mounted-over entry. The test is skipped where that cannot be set
// up (no unshare(1), sh or mount(8), or no right to mount).
func garbledTimensOffsetsWrapper(t *testing.T) []string {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("unshare(1) not found: %v", err)
	}
	garbled := filepath.Join(t.TempDir(), "timens_offsets")
	if err := os.WriteFile(garbled, []byte(garbledTimensOffsets), 0o644); err != nil {
		t.Fatal(err)
	}
	// $0 is the garbled file, "$@" the program and its arguments.
	const script = `mount --bind "$0" "/proc/$$/timens_offsets" && exec "$@"`
	wrapper := []string{unshare, "--mount", "--", "sh", "-c", script, garbled}
	probe := slices.Concat(wrapper[1:], []string{"cat", "/proc/self/timens_offsets"})
	out, err := exec.Command(unshare, probe...).CombinedOutput()
	if err != nil || string(out) != garbledTimensOffsets {
		t.Skipf("cannot mount a file over /proc/self/timens_offsets: %v: %q", err, out)
	}
	return wrapper
}
