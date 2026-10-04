package internal

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Task zs2: event-loop fixtures name made-up processes, and every descriptor
// or comm the loop has not seen traced falls back to procfs
// (/proc/<pid>/fd/<fd>, /proc/<tid>/comm). A fixture pid such as 7100, 4242 or
// 10 is an ordinary pid, so on a host where it happens to be alive the
// fallback answers with that process's real descriptor (procfs said
// "anon_inode:[eventfd]" for fd 3 of a live pid 7100) and a test expecting "no
// such process" fails - or, worse, a negative control passes for the wrong
// reason.
//
// absentPidBase is PID_MAX_LIMIT of 64-bit Linux (4 * 1024 * 1024, the 32-bit
// limit is far lower): /proc/sys/kernel/pid_max cannot be raised above it and
// the kernel allocates pids strictly below pid_max, in every pid namespace. No
// task on any host can therefore have a pid or tid at or above it, so a fixture
// built from absentPid sees exactly the procfs answer of a process that has
// gone (ENOENT), which is what those tests assume, through the real procfs
// path rather than a fake root. Fixtures whose outcome depends on the procfs
// fallback are written absentPidBase + n, n being the fixture's old small
// number so it stays recognisable (absentPidBase + 4242 prints as 4198546);
// tests that need a live process use their own pid or a child they start
// (TestRealForkedChildKeepsInheritedNamesAgainstProcfs).
//
// Why not a fake procfs root as checkTraceTarget and resolveCommFromProcRoot
// take: the descriptor fallback lives in package file (file.NewFdWithPid,
// probeHandleFd) and reads /proc directly, and a fake root would only cover
// the readers that were plumbed through it. A pid that cannot exist keeps
// every reader, present and future, on the "process gone" path.
const absentPidBase = 1 << 22

// TestAbsentPidsCannotExistOnThisHost pins the premise of absentPidBase on the
// host running the suite: pid_max does not exceed it and none of the shared
// fixture pids has a /proc entry. A failure here explains the procfs-dependent
// failures elsewhere instead of leaving them to look like event-loop bugs.
func TestAbsentPidsCannotExistOnThisHost(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Skipf("pid_max unreadable (no procfs?): %v", err)
	}
	pidMax, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		t.Fatalf("parse pid_max %q: %v", raw, err)
	}
	if pidMax > absentPidBase {
		t.Fatalf("pid_max = %d exceeds absentPidBase %d: fixture pids could be alive", pidMax, absentPidBase)
	}
	for _, pid := range []uint32{defaultPid, defaultTid, execCommPid, execCommTid, forkParentPid, forkChildPid} {
		if _, err := os.Lstat(procTidPathPrefix(pid)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("fixture pid %d: /proc entry lookup err = %v, want not-exist", pid, err)
		}
	}
}
