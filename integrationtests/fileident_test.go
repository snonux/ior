package integrationtests

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"

	iorparquet "ior/internal/parquet"
)

// Task 603 end to end: the kernel program says which file a descriptor named
// when a call entered, and ior names a row only after that file.

// requireFileIdentCapture skips a test that needs the capture on a kernel
// whose BPF cannot run it: the walk needs the bpf_rdonly_cast kfunc (Linux
// 6.2), and without it every identity is 0 and rows are named as before.
func requireFileIdentCapture(t *testing.T) {
	t.Helper()
	requireRootForProbe(t)
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		t.Skipf("cannot read /proc/kallsyms to look for bpf_rdonly_cast: %v", err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if fields := strings.Fields(scanner.Text()); len(fields) >= 3 && fields[2] == "bpf_rdonly_cast" {
			return
		}
	}
	t.Skip("kernel has no bpf_rdonly_cast kfunc: no file identity capture")
}

// iouringReopenRows runs the iouring-reopen scenario with iorEnv added to
// ior's environment and returns its rows.
func iouringReopenRows(t *testing.T, iorEnv ...string) []iorparquet.Record {
	t.Helper()
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	h.IorEnv = iorEnv
	path, pid, err := h.RunParquetWithIorArgs("iouring-reopen", defaultDuration, nil)
	if err != nil {
		t.Fatalf("run parquet scenario iouring-reopen: %v", err)
	}
	rows := readParquetRecords(t, path)
	assertParquetRowsOwnedBy(t, rows, uint32(pid), "ioworkload")
	return rows
}

// preadNames returns the file names of the scenario's pread64 rows that read
// size bytes: 3 before the descriptor was rebound, 5 after.
func preadNames(rows []iorparquet.Record, size int64) []string {
	var names []string
	for _, row := range rows {
		if row.Syscall == "pread64" && row.Ret == size {
			names = append(names, row.File)
		}
	}
	return names
}

// requireAllContain fails unless there are at least min names and each
// contains want.
func requireAllContain(t *testing.T, what string, names []string, min int, want string) {
	t.Helper()
	if len(names) < min {
		t.Fatalf("%s: %d rows %q, want at least %d", what, len(names), names, min)
	}
	for _, name := range names {
		if !strings.Contains(name, want) {
			t.Errorf("%s: row named %q, want a name containing %q", what, name, want)
		}
	}
}

// TestIouringReopenRowsFollowTheFile is the task's live case. The workload
// opens a file with openat(2), then closes the descriptor with
// IORING_OP_CLOSE and opens a second file with IORING_OP_OPENAT, which lands
// on the same number: no syscall tells ior about either. Its preads before
// that must carry the first file's name and the preads after it the second's
// (they used to keep the first's, as did the final close).
func TestIouringReopenRowsFollowTheFile(t *testing.T) {
	requireIoUring(t)
	requireFileIdentCapture(t)
	rows := iouringReopenRows(t)

	requireAllContain(t, "preads before the reopen", preadNames(rows, 3), 2, "iouring-reopen-first.txt")
	requireAllContain(t, "preads after the reopen", preadNames(rows, 5), 3, "iouring-reopen-second.txt")
	// The workload closed the descriptor it wrote the first file with before
	// any of this, rightly under that name; the close after the reads of the
	// second file is the rebound descriptor's.
	var closedSecond bool
	for _, row := range rows {
		if row.Syscall != "close" || row.TimeNS < lastPreadTime(rows, 5) {
			continue
		}
		if strings.Contains(row.File, "iouring-reopen-first.txt") {
			t.Errorf("close of the rebound descriptor is named after the first file: %+v", row)
		}
		closedSecond = closedSecond || strings.Contains(row.File, "iouring-reopen-second.txt")
	}
	if !closedSecond {
		t.Error("no close row after the reopen is named after the second file")
		logRowSummary(t, rows)
	}
}

// lastPreadTime returns the time of the last pread64 row that read size
// bytes, or 0 when there is none.
func lastPreadTime(rows []iorparquet.Record, size int64) uint64 {
	var last uint64
	for _, row := range rows {
		if row.Syscall == "pread64" && row.Ret == size {
			last = max(last, row.TimeNS)
		}
	}
	return last
}

// TestIouringReopenWithoutFileIdentityKeepsTheOpenedName is the control: with
// the capture switched off (IOR_FILE_IDENT=0 compiles the walk out of the
// loaded programs) the same run shows the documented limitation, every pread
// under the name the traced openat gave the number. It proves the test above
// passes because of the identity, and that the switch reaches the kernel
// program.
func TestIouringReopenWithoutFileIdentityKeepsTheOpenedName(t *testing.T) {
	requireIoUring(t)
	rows := iouringReopenRows(t, "IOR_FILE_IDENT=0")

	requireAllContain(t, "preads before the reopen", preadNames(rows, 3), 2, "iouring-reopen-first.txt")
	requireAllContain(t, "preads after the reopen, capture off", preadNames(rows, 5), 3, "iouring-reopen-first.txt")
}

// TestCloseUntrackedWritesAreNeverNamedAfterTheReusingPipe is task yz2 end to
// end, on the close-untracked workload: each descriptor opened before ior
// attached is written to and at once closed, and a pipe takes its number.
// ior resolves such a write through /proc/<pid>/fd when it gets to the row,
// mostly after the pipe is there, and used to report the write on the pipe
// (and cache that for the number). The write's record says which file it
// wrote, so the pipe's answer is refused. The first descriptor is written
// while it is still open, so its write is named - which also shows that the
// kernel's identity and procfs's agree for a regular file.
func TestCloseUntrackedWritesAreNeverNamedAfterTheReusingPipe(t *testing.T) {
	requireFileIdentCapture(t)
	rows := closeUntrackedRows(t)

	writes, named, afterPipe := closeUntrackedWriteNames(t, rows)
	if afterPipe != 0 {
		t.Errorf("%d of %d writes are named after the pipe that reused their number", afterPipe, writes)
	}
	if writes < 65 || named < 1 {
		t.Errorf("%d write rows, %d named after their file; want >= 65 rows and the first one named", writes, named)
		logRowSummary(t, rows)
	}
	// The write that was blocked across the close and the pipe: ior always
	// gets to it after the pipe2 that rebound the number, and the identity
	// (with the binding time of the pipe's entry) refuses the pipe.
	if name := blockedFifoWriteName(t, rows); name != "" {
		t.Errorf("blocked fifo write named %q, want no name", name)
	}
	assertCloseUntrackedRows(t, rows)
}

// blockedFifoWriteName returns the file name of close-untracked's blocked
// FIFO write (the one write of closeUntrackedBlockedBytes, 256 KiB, in
// cmd/ioworkload), and fails the test unless there is exactly one.
func blockedFifoWriteName(t *testing.T, rows []iorparquet.Record) string {
	t.Helper()
	const blockedBytes = 256 * 1024
	var names []string
	for _, row := range rows {
		if row.Syscall == "write" && row.Ret == blockedBytes {
			names = append(names, row.File)
		}
	}
	if len(names) != 1 {
		t.Fatalf("%d write rows of %d bytes %q, want the one blocked fifo write", len(names), blockedBytes, names)
	}
	return names[0]
}

// closeUntrackedRows runs the close-untracked scenario with iorEnv added to
// ior's environment and returns its rows.
func closeUntrackedRows(t *testing.T, iorEnv ...string) []iorparquet.Record {
	t.Helper()
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	h.IorEnv = iorEnv
	path, pid, err := h.RunParquetWithIorArgs("close-untracked", defaultDuration, nil)
	if err != nil {
		t.Fatalf("run parquet scenario close-untracked: %v", err)
	}
	rows := readParquetRecords(t, path)
	assertParquetRowsOwnedBy(t, rows, uint32(pid), "ioworkload")
	return rows
}

// closeUntrackedWriteNames counts the scenario's write rows: all of them,
// those named after the file they wrote, and those named after a pipe (the
// file that took the number afterwards; each is logged).
func closeUntrackedWriteNames(t *testing.T, rows []iorparquet.Record) (writes, named, afterPipe int) {
	t.Helper()
	for _, row := range rows {
		if row.Syscall != "write" {
			continue
		}
		writes++
		if strings.Contains(row.File, "pipe") {
			afterPipe++
			t.Logf("write to fd %d is named after the pipe that reused the number: %q", row.FD, row.File)
		}
		if strings.Contains(row.File, "closeuntracked-") {
			named++
		}
	}
	return writes, named, afterPipe
}

// TestCloseUntrackedWritesWithoutFileIdentityAreNamedAfterTheReusingPipe is
// the control of the test above: with the capture switched off the same run
// shows task yz2's defect, writes reported on the pipe that took the number
// after them. It proves that the test above passes because the answers are
// checked against the identity, not because the workload stopped racing the
// event loop.
//
// The 63 write-close-pipe iterations race the loop, and on an idle host the
// loop can win every one of them; so the control asks for the one write the
// loop cannot win (task a23): the workload's last write blocks on a full FIFO
// in a thread of its own while the main thread closes the descriptor, puts a
// pipe on the number and only then drains the FIFO. The write's exit record,
// where ior resolves it, comes after the pipe2 exit, so by then the number is
// the pipe's in ior's fd table (pipe2 is traced) and in /proc/<pid>/fd alike.
func TestCloseUntrackedWritesWithoutFileIdentityAreNamedAfterTheReusingPipe(t *testing.T) {
	rows := closeUntrackedRows(t, "IOR_FILE_IDENT=0")

	writes, _, afterPipe := closeUntrackedWriteNames(t, rows)
	if writes < 65 || afterPipe < 1 {
		t.Errorf("%d write rows, %d named after the reusing pipe; want >= 65 rows and at least one such write with the capture off",
			writes, afterPipe)
		logRowSummary(t, rows)
	}
	if name := blockedFifoWriteName(t, rows); !strings.Contains(name, "pipe") {
		t.Errorf("blocked fifo write named %q, want the reusing pipe with the capture off", name)
	}
}

// TestCloseUntrackedClosesAreNamedByTheirLastComponent is task xz2 end to
// end, on the close-untracked workload: 64 files and a FIFO are opened
// before ior attaches, so their closes have no fd table entry, and each
// number is taken by a pipe at once. Such a close was unnamed unless a
// write row had read procfs before the close began. The kernel program now
// reads the file's last path component as the close enters, so every one of
// the 65 closes is named: in full where procfs was read in time, else as
// "*/closeuntracked-N.txt".
//
// The FIFO's close is the deterministic one. Its descriptor is only ever
// used by the write that is still blocked when the close happens, so no row
// resolved it before; without the capture that close has no name whatever
// the load (the control below).
func TestCloseUntrackedClosesAreNamedByTheirLastComponent(t *testing.T) {
	requireFileIdentCapture(t)
	rows := closeUntrackedRows(t)

	names := closeNamesByLeaf(rows, "closeuntracked-")
	for i := range 64 {
		leaf := fmt.Sprintf("closeuntracked-%d.txt", i)
		if got := names[leaf]; len(got) != 1 {
			t.Errorf("closes named after %s: %q, want exactly one", leaf, got)
		}
	}
	if got := names["closeuntracked-fifo"]; len(got) != 1 || got[0] != "*/closeuntracked-fifo" {
		t.Errorf("close of the fifo's write descriptor named %q, want the one name */closeuntracked-fifo", got)
	}
	if t.Failed() {
		logRowSummary(t, rows)
	}
	assertCloseUntrackedRows(t, rows)
}

// TestCloseUntrackedClosesWithoutFileIdentityStayUnnamed is the control of
// the test above: with the capture switched off the kernel program sends no
// component, so no row carries the "*/" form and the FIFO's close - which no
// procfs read can name - has no name.
func TestCloseUntrackedClosesWithoutFileIdentityStayUnnamed(t *testing.T) {
	rows := closeUntrackedRows(t, "IOR_FILE_IDENT=0")

	closes := 0
	for _, row := range rows {
		if row.Syscall != "close" {
			continue
		}
		closes++
		if strings.HasPrefix(row.File, "*/") {
			t.Errorf("close of fd %d is named by a component with the capture off: %q", row.FD, row.File)
		}
	}
	if got := closeNamesByLeaf(rows, "closeuntracked-")["closeuntracked-fifo"]; len(got) != 0 || closes < 65 {
		t.Errorf("%d close rows, fifo close named %q; want >= 65 rows and no name for the fifo's close", closes, got)
		logRowSummary(t, rows)
	}
}

// closeNamesByLeaf returns the file names of the close rows whose name has a
// last path component starting with prefix, by that component: the full path
// of a row named from procfs or a traced open and the "*/leaf" form alike.
func closeNamesByLeaf(rows []iorparquet.Record, prefix string) map[string][]string {
	names := map[string][]string{}
	for _, row := range rows {
		leaf := row.File[strings.LastIndex(row.File, "/")+1:]
		if row.Syscall == "close" && strings.HasPrefix(leaf, prefix) {
			names[leaf] = append(names[leaf], row.File)
		}
	}
	return names
}
