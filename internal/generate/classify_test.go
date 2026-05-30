package generate

import (
	"strconv"
	"strings"
	"testing"
)

func classifyFromData(t *testing.T, data string) ClassificationResult {
	t.Helper()
	f := mustParseOne(t, data)
	return ClassifyFormat(&f)
}

func TestClassifyFdRead(t *testing.T) {
	r := classifyFromData(t, FormatRead)
	if r.Kind != KindFd {
		t.Errorf("read: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyFdClose(t *testing.T) {
	r := classifyFromData(t, FormatClose)
	if r.Kind != KindFd {
		t.Errorf("close: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyFdPread64(t *testing.T) {
	r := classifyFromData(t, FormatPread64)
	if r.Kind != KindFd {
		t.Errorf("pread64: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyFdWrite(t *testing.T) {
	r := classifyFromData(t, FormatWrite)
	if r.Kind != KindFd {
		t.Errorf("write: got kind %d, want KindFd", r.Kind)
	}
}

// TestClassifyFdLseek pins lseek(2) as a single-fd KindFd event. lseek's
// tracepoint exposes a generic "fd" field of an fd-like type at args[0], so it
// classifies via classifyByField exactly like read/write — the fd is captured
// from args[0], while the off_t offset and whence args are ignored. The return
// value (resulting file offset) is asserted UNCLASSIFIED separately in
// retclassify_test.go (TestClassifyRetUnclassified) and end-to-end in
// TestClassifyRetExitLseek below.
func TestClassifyFdLseek(t *testing.T) {
	r := classifyFromData(t, FormatLseek)
	if r.Kind != KindFd {
		t.Errorf("lseek: got kind %d, want KindFd", r.Kind)
	}
}

// TestClassifyRetExitLseek locks in that sys_exit_lseek is a plain ret_event
// (KindRet) and that ClassifyRet keeps it UNCLASSIFIED. lseek returns the new
// file OFFSET (bytes-from-start), not a transferred byte count, so it must
// never be classified as READ/WRITE/TRANSFER — doing so would inflate I/O byte
// accounting.
func TestClassifyRetExitLseek(t *testing.T) {
	r := classifyFromData(t, FormatExitLseek)
	if r.Kind != KindRet {
		t.Errorf("lseek exit: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_lseek"); got != Unclassified {
		t.Errorf("lseek exit: ClassifyRet = %q, want UNCLASSIFIED", got)
	}
}

func TestClassifyFdPidfdGetfd(t *testing.T) {
	r := classifyFromData(t, FormatPidfdGetfd)
	if r.Kind != KindFd {
		t.Errorf("pidfd_getfd: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyOpenOpenat(t *testing.T) {
	r := classifyFromData(t, FormatOpenat)
	if r.Kind != KindOpen {
		t.Errorf("openat: got kind %d, want KindOpen", r.Kind)
	}
}

func TestClassifyOpenOpen(t *testing.T) {
	r := classifyFromData(t, FormatOpen)
	if r.Kind != KindOpen {
		t.Errorf("open: got kind %d, want KindOpen", r.Kind)
	}
}

func TestClassifyOpenOpenat2(t *testing.T) {
	r := classifyFromData(t, FormatOpenat2)
	if r.Kind != KindOpen {
		t.Errorf("openat2: got kind %d, want KindOpen", r.Kind)
	}
}

func TestClassifyPathnameCreat(t *testing.T) {
	r := classifyFromData(t, FormatCreat)
	if r.Kind != KindPathname {
		t.Errorf("creat: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "pathname" {
		t.Errorf("creat: PathnameField = %q, want pathname", r.PathnameField)
	}
}

func TestClassifyPathnameUnlink(t *testing.T) {
	r := classifyFromData(t, FormatUnlink)
	if r.Kind != KindPathname {
		t.Errorf("unlink: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "pathname" {
		t.Errorf("unlink: PathnameField = %q, want pathname", r.PathnameField)
	}
}

// TestClassifyPathnameUtime locks in that utime's args[0] "filename" is
// captured as a real path. utime(2) changes a file's access/modification
// times; its filename argument is a genuine filesystem path (not a
// domain/host name string), so it must classify as KindPathname with the
// path wired to the "filename" field — matching siblings utimensat/futimesat.
func TestClassifyPathnameUtime(t *testing.T) {
	r := classifyFromData(t, FormatUtime)
	if r.Kind != KindPathname {
		t.Errorf("utime: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "filename" {
		t.Errorf("utime: PathnameField = %q, want filename", r.PathnameField)
	}
}

// TestClassifyPathnameAccess locks in that access(2)'s args[0] argument
// (kernel field "filename") is captured as a real filesystem path. access(2)
// checks the calling process's permissions for a file by path; the path is at
// args[0] (there is no dirfd), so it must classify as KindPathname with the
// path wired to the "filename" field. If this regresses to a non-path kind,
// access's pathname would silently stop being captured.
func TestClassifyPathnameAccess(t *testing.T) {
	r := classifyFromData(t, FormatAccess)
	if r.Kind != KindPathname {
		t.Errorf("access: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "filename" {
		t.Errorf("access: PathnameField = %q, want filename", r.PathnameField)
	}
}

// TestClassifyPathnameFaccessat locks in that faccessat(2) — access(2)'s
// dirfd-relative sibling — also classifies as KindPathname with the path wired
// to the "filename" field. The path is at args[1] (args[0] is the dirfd); the
// argument-index difference from access(2) is verified separately in the
// codegen tests (TestGenerateAccessFaccessatHandlers).
func TestClassifyPathnameFaccessat(t *testing.T) {
	r := classifyFromData(t, FormatFaccessat)
	if r.Kind != KindPathname {
		t.Errorf("faccessat: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "filename" {
		t.Errorf("faccessat: PathnameField = %q, want filename", r.PathnameField)
	}
}

func TestClassifyNameRename(t *testing.T) {
	r := classifyFromData(t, FormatRename)
	if r.Kind != KindName {
		t.Errorf("rename: got kind %d, want KindName", r.Kind)
	}
}

func TestClassifyNameLinkat(t *testing.T) {
	r := classifyFromData(t, FormatLinkat)
	if r.Kind != KindName {
		t.Errorf("linkat: got kind %d, want KindName", r.Kind)
	}
}

func TestClassifyNameSymlink(t *testing.T) {
	r := classifyFromData(t, FormatSymlink)
	if r.Kind != KindName {
		t.Errorf("symlink: got kind %d, want KindName", r.Kind)
	}
}

func TestClassifyFcntl(t *testing.T) {
	r := classifyFromData(t, FormatFcntl)
	if r.Kind != KindFcntl {
		t.Errorf("fcntl: got kind %d, want KindFcntl", r.Kind)
	}
}

func TestClassifyDup(t *testing.T) {
	r := classifyFromData(t, FormatDup)
	if r.Kind != KindFd {
		t.Errorf("dup: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyDup2(t *testing.T) {
	r := classifyFromData(t, FormatDup2)
	if r.Kind != KindFd {
		t.Errorf("dup2: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyDup3(t *testing.T) {
	r := classifyFromData(t, FormatDup3)
	if r.Kind != KindDup3 {
		t.Errorf("dup3: got kind %d, want KindDup3", r.Kind)
	}
}

func TestClassifyOpenByHandleAt(t *testing.T) {
	r := classifyFromData(t, FormatOpenByHandleAt)
	if r.Kind != KindOpenByHandleAt {
		t.Errorf("open_by_handle_at: got kind %d, want KindOpenByHandleAt", r.Kind)
	}
}

func TestClassifyNameToHandleAt(t *testing.T) {
	r := classifyFromData(t, FormatNameToHandleAt)
	if r.Kind != KindPathname {
		t.Errorf("name_to_handle_at: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "name" {
		t.Errorf("name_to_handle_at: PathnameField = %q, want name", r.PathnameField)
	}
}

func TestClassifyNullSync(t *testing.T) {
	r := classifyFromData(t, FormatSync)
	if r.Kind != KindNull {
		t.Errorf("sync: got kind %d, want KindNull", r.Kind)
	}
}

func TestClassifyNullSyslog(t *testing.T) {
	r := classifyFromData(t, FormatSyslog)
	if r.Kind != KindNull {
		t.Errorf("syslog: got kind %d, want KindNull", r.Kind)
	}
}

// TestClassifyNullGetcwd pins getcwd as KindNull at enter.
//
// getcwd's args[0] is `char *buf`, an OUTPUT buffer: the kernel writes the
// absolute cwd path into it and the contents only become valid AFTER the
// syscall returns (sys_exit). Reading buf at enter would capture an empty or
// garbage string, so getcwd must NOT be classified as a path-input syscall.
// KindNull is the correct enter kind; the cwd is resolved at exit from
// /proc/<tid>/cwd (see eventLoop.handleNullExit). This test locks that in:
//   - the enter kind is KindNull (not KindPathname/KindName), and
//   - no pathname field is captured from the buffer at enter.
func TestClassifyNullGetcwd(t *testing.T) {
	r := classifyFromData(t, FormatGetcwd)
	if r.Kind != KindNull {
		t.Errorf("getcwd: got kind %d, want KindNull", r.Kind)
	}
	if r.Kind == KindPathname || r.Kind == KindName {
		t.Errorf("getcwd: enter must not capture output buf as a path, got kind %d", r.Kind)
	}
	if r.PathnameField != "" {
		t.Errorf("getcwd: no enter-time pathname field expected, got %q", r.PathnameField)
	}
}

// TestClassifyByFieldGetcwdBufNotPath is a defense-in-depth lock-in: even if
// the name-only KindNull override for getcwd were removed, the generic
// field-based classifier must not treat `char *buf` as a pathname. Only the
// field names pathname/path/filename/newname are path-like; "buf" is not, so
// classifyByField must report no match for getcwd's output buffer.
func TestClassifyByFieldGetcwdBufNotPath(t *testing.T) {
	if r, ok := classifyByField("char *", "buf"); ok {
		t.Errorf("getcwd buf: char *buf must not classify as a field kind, got %d", r.Kind)
	}
}

func TestClassifyNullIoUring(t *testing.T) {
	r := classifyFromData(t, FormatIoUringEnter)
	if r.Kind != KindFd {
		t.Errorf("io_uring_enter: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyIoUringRegister(t *testing.T) {
	r := classifyFromData(t, FormatIoUringRegister)
	if r.Kind != KindFd {
		t.Errorf("io_uring_register: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyRetExitRead(t *testing.T) {
	r := classifyFromData(t, FormatExitRead)
	if r.Kind != KindRet {
		t.Errorf("exit_read: got kind %d, want KindRet", r.Kind)
	}
}

func TestClassifyRetExitWrite(t *testing.T) {
	r := classifyFromData(t, FormatExitWrite)
	if r.Kind != KindRet {
		t.Errorf("exit_write: got kind %d, want KindRet", r.Kind)
	}
}

func TestClassifyRetExitOpenat(t *testing.T) {
	r := classifyFromData(t, FormatExitOpenat)
	if r.Kind != KindRet {
		t.Errorf("exit_openat: got kind %d, want KindRet", r.Kind)
	}
}

func TestClassifyRetExitPread64(t *testing.T) {
	r := classifyFromData(t, FormatExitPread64)
	if r.Kind != KindRet {
		t.Errorf("exit_pread64: got kind %d, want KindRet", r.Kind)
	}
}

func TestClassifyRetExitSymlink(t *testing.T) {
	r := classifyFromData(t, FormatExitSymlink)
	if r.Kind != KindRet {
		t.Errorf("exit_symlink: got kind %d, want KindRet", r.Kind)
	}
}

func TestClassifyPathnameMknod(t *testing.T) {
	r := classifyFromData(t, FormatMknod)
	if r.Kind != KindPathname {
		t.Errorf("mknod: got kind %d, want KindPathname", r.Kind)
	}
}

func TestClassifyExecExecve(t *testing.T) {
	r := classifyFromData(t, FormatExecve)
	if r.Kind != KindExec {
		t.Errorf("execve: got kind %d, want KindExec", r.Kind)
	}
}

func TestClassifyExecExecveat(t *testing.T) {
	r := classifyFromData(t, FormatExecveat)
	if r.Kind != KindExec {
		t.Errorf("execveat: got kind %d, want KindExec", r.Kind)
	}
}

func TestClassifyAccept(t *testing.T) {
	r := classifyFromData(t, FormatAccept)
	if r.Kind != KindAccept {
		t.Errorf("accept: got kind %d, want KindAccept", r.Kind)
	}
}

func TestClassifyAccept4(t *testing.T) {
	r := classifyFromData(t, FormatAccept4)
	if r.Kind != KindAccept {
		t.Errorf("accept4: got kind %d, want KindAccept", r.Kind)
	}
}

func TestClassifyExitAccept(t *testing.T) {
	r := classifyFromData(t, FormatExitAccept)
	if r.Kind != KindAccept {
		t.Errorf("exit_accept: got kind %d, want KindAccept", r.Kind)
	}
}

func TestClassifyExitAccept4(t *testing.T) {
	r := classifyFromData(t, FormatExitAccept4)
	if r.Kind != KindAccept {
		t.Errorf("exit_accept4: got kind %d, want KindAccept", r.Kind)
	}
}

func TestClassifySocketFdSyscallsByName(t *testing.T) {
	tests := []string{
		"bind",
		"connect",
		"listen",
		"shutdown",
		"getsockname",
		"getpeername",
		"getsockopt",
		"setsockopt",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: "sys_enter_" + name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "int", Name: "sockfd"},
				},
			})
			if r.Kind != KindFd {
				t.Errorf("%s: got kind %d, want KindFd", name, r.Kind)
			}
		})
	}
}

// TestClassifySyncFamilyFdSyscallsByName locks in that the filesystem-sync
// family (fsync/fdatasync/syncfs/sync_file_range) is classified as KindFd on
// enter. Each of these takes an open file descriptor as args[0]:
//   - int fsync(int fd)
//   - int fdatasync(int fd)
//   - int syncfs(int fd)
//   - int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned flags)
//
// so their enter tracepoint carries a leading fd field and must capture
// fd=args[0] into a fd_event (KindFd), matching the generated
// handle_sys_enter_* handlers. (Plain sync() takes no args and is KindNull;
// it is asserted separately in the classification table test.)
func TestClassifySyncFamilyFdSyscallsByName(t *testing.T) {
	tests := []string{
		"fsync",
		"fdatasync",
		"syncfs",
		"sync_file_range",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: "sys_enter_" + name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "int", Name: "fd"},
				},
			})
			if r.Kind != KindFd {
				t.Errorf("%s: got kind %d, want KindFd", name, r.Kind)
			}
		})
	}
}

// TestClassifyExitSyncfs locks in that the syncfs exit tracepoint is classified
// as KindRet. syncfs(2) returns int (0 on success, -1 on error) and transfers
// no bytes, so its exit format carries a single "ret" field and must map to a
// plain ret_event (KindRet, Unclassified) — matching the generated
// sys_exit_syncfs handler and its fsync/fdatasync siblings.
func TestClassifyExitSyncfs(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_syncfs",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Errorf("exit_syncfs: got kind %d, want KindRet", r.Kind)
	}
}

// TestClassifyFallocateEnterFd locks in that the fallocate enter tracepoint is
// classified as KindFd with the fd captured at args[0].
//
//	int fallocate(int fd, int mode, off_t offset, off_t len)
//
// fallocate(2) manipulates the allocated disk space for the file referred to
// by fd (args[0]); the remaining mode/offset/len args are NOT captured, exactly
// like its fd-based siblings fadvise64(2)/ftruncate(2)/sync_file_range(2) which
// also carry trailing offset/len/advice args but only record args[0]. The
// leading "fd" external field must select KindFd so the generated
// handle_sys_enter_fallocate emits ev->fd = ctx->args[0] into a fd_event.
func TestClassifyFallocateEnterFd(t *testing.T) {
	f := &Format{
		Name: "sys_enter_fallocate",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "mode"},
			{Type: "loff_t", Name: "offset"},
			{Type: "loff_t", Name: "len"},
		},
	}
	r := ClassifyFormat(f)
	if r.Kind != KindFd {
		t.Fatalf("enter_fallocate: got kind %d, want KindFd", r.Kind)
	}
	// fd is the first real argument (args[0]); FieldNumber skips __syscall_nr.
	if got := f.FieldNumber("fd"); got != 0 {
		t.Errorf("enter_fallocate: fd field number = %d, want 0 (args[0])", got)
	}
}

// TestClassifyExitFallocateUnclassifiedRet locks in that the fallocate exit
// tracepoint is classified as KindRet and Unclassified. fallocate(2) returns
// int (0 on success, -1 on error) — that return is a status code, NOT a
// transferred byte count, so its exit format carries a single "ret" field and
// must map to a plain ret_event (KindRet) whose ret_type stays UNCLASSIFIED.
// Misclassifying it as a READ/WRITE/TRANSFER byte count would be a real bug,
// since fallocate allocates space but reports no transferred bytes.
func TestClassifyExitFallocateUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_fallocate",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_fallocate: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_fallocate"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_fallocate) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifySetuidNullEnter locks in that the setuid enter tracepoint is
// classified as KindNull. setuid(2) is "int setuid(uid_t uid)" — its single
// argument is a numeric user ID, NOT a file descriptor or a path. It must
// therefore map to a null_event (no argument capture); misclassifying it as an
// fd-bearing kind would be a real bug, since the uid is not an fd and capturing
// it as one would attribute the credential change to a bogus file. The whole
// credential-setting cluster (setuid/seteuid/setresuid/setreuid/setfsuid and
// the gid analogues) shares this KindNull treatment with the getuid readers.
func TestClassifySetuidNullEnter(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_setuid",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "uid"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("enter_setuid: got kind %d, want KindNull", r.Kind)
	}
	// The uid argument must never be captured as a file descriptor or path.
	if r.PathnameField != "" {
		t.Errorf("enter_setuid: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitSetuidUnclassifiedRet locks in that the setuid exit
// tracepoint is classified as KindRet and Unclassified. setuid(2) returns int
// (0 on success, -1 on error) — that return is a status code, NOT a
// transferred byte count, so its exit format carries a single "ret" field and
// must map to a plain ret_event (KindRet) whose ret_type stays UNCLASSIFIED.
// Misclassifying it as a READ/WRITE/TRANSFER byte count would be a real bug.
func TestClassifyExitSetuidUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_setuid",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_setuid: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_setuid"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_setuid) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifySetpgidNullEnter locks in the setpgid(2) enter classification
// using the syscall's REAL tracepoint fields. setpgid(pid_t pid, pid_t pgid)
// sets the process group ID of a process; both arguments are process/process-
// group identifiers (the kernel tracepoint declares them as field type
// "pid_t"), NOT file descriptors and NOT filesystem paths. The audit concern is
// that args[0] ("pid") could be mistaken for an fd: it must not be. setpgid has
// no fd or path argument, so its enter format must classify as KindNull
// (null_event) — matching its session/process-group siblings setsid/getsid/
// getpgid/getpgrp and the explicit name-only mapping in classify.go. Using the
// real "pid"/"pgid" pid_t fields here (rather than a synthetic arg0) proves the
// generic field heuristics never capture them: isFdType only matches int/
// unsigned int/unsigned long (not "pid_t"), and the fd heuristic additionally
// requires the field name be "fd", which neither "pid" nor "pgid" is.
func TestClassifySetpgidNullEnter(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_setpgid",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "pid_t", Name: "pgid"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("enter_setpgid: got kind %d, want KindNull", r.Kind)
	}
	// Neither pid argument must be captured as a file descriptor or path.
	if r.PathnameField != "" {
		t.Errorf("enter_setpgid: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitSetpgidUnclassifiedRet locks in that the setpgid exit
// tracepoint is classified as KindRet and Unclassified. setpgid(2) returns int
// (0 on success, -1 on error) — a status code, NOT a transferred byte count —
// so its exit format carries a single "ret" field and must map to a plain
// ret_event (KindRet) whose ret_type stays UNCLASSIFIED. This matches its
// sibling setsid/getsid (asserted in retclassify_test.go); misclassifying it as
// a READ/WRITE/TRANSFER byte count would be a real bug.
func TestClassifyExitSetpgidUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_setpgid",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_setpgid: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_setpgid"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_setpgid) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifyGetgidNullEnter locks in the getgid(2) enter classification using
// the syscall's REAL tracepoint fields. getgid(2) is "gid_t getgid(void)" — it
// takes NO arguments at all, so its enter format carries only the synthetic
// __syscall_nr field and must classify as KindNull (null_event capturing
// nothing). This matches the no-arg id-returning reader cluster
// getuid/geteuid/getegid/getpid/getppid/gettid and the explicit name-only
// mapping in classify.go. With no real argument fields there is nothing the fd
// or path heuristics could latch onto, so PathnameField must stay empty.
func TestClassifyGetgidNullEnter(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_getgid",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("enter_getgid: got kind %d, want KindNull", r.Kind)
	}
	// getgid has no arguments, so nothing must be captured as a path/fd.
	if r.PathnameField != "" {
		t.Errorf("enter_getgid: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitGetgidUnclassifiedRet locks in that the getgid exit
// tracepoint is classified as KindRet and Unclassified. getgid(2) returns the
// real group ID (gid_t) of the caller and ALWAYS succeeds — its return is a
// numeric credential identifier, NOT a transferred byte count and never an
// error status. Its exit format carries a single "ret" field and must map to a
// plain ret_event (KindRet) whose ret_type stays UNCLASSIFIED. Misclassifying
// the gid as a READ/WRITE/TRANSFER byte count would be a real bug. This matches
// its no-arg reader siblings getuid/getpid (no byte semantics on their return).
func TestClassifyExitGetgidUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_getgid",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_getgid: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_getgid"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_getgid) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifyGettidNullEnter locks in the gettid(2) enter classification using
// the syscall's REAL tracepoint fields. gettid(2) is "pid_t gettid(void)" — it
// takes NO arguments at all, so its enter format carries only the synthetic
// __syscall_nr field and must classify as KindNull (null_event capturing
// nothing). This matches the no-arg id-returning reader cluster
// getuid/geteuid/getegid/getpid/getppid/getgid and the explicit name-only
// mapping in classify.go. With no real argument fields there is nothing the fd
// or path heuristics could latch onto, so PathnameField must stay empty.
func TestClassifyGettidNullEnter(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_gettid",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("enter_gettid: got kind %d, want KindNull", r.Kind)
	}
	// gettid has no arguments, so nothing must be captured as a path/fd.
	if r.PathnameField != "" {
		t.Errorf("enter_gettid: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitGettidUnclassifiedRet locks in that the gettid exit
// tracepoint is classified as KindRet and Unclassified. gettid(2) returns the
// caller's thread ID (pid_t) and ALWAYS succeeds — its return is a numeric
// thread identifier, NOT a transferred byte count and never an error status.
// Its exit format carries a single "ret" field and must map to a plain
// ret_event (KindRet) whose ret_type stays UNCLASSIFIED. Misclassifying the tid
// as a READ/WRITE/TRANSFER byte count would be a real bug. This matches its
// no-arg reader siblings getuid/getpid/getgid (no byte semantics on their
// return).
func TestClassifyExitGettidUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_gettid",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_gettid: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_gettid"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_gettid) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifyExitGetpeername locks in that the getpeername exit tracepoint is
// classified as KindRet. getpeername(2) returns int (0 on success, -1 on
// error), so its exit format carries a single "ret" field and must map to a
// plain ret_event, matching the generated sys_exit_getpeername handler.
func TestClassifyExitGetpeername(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_getpeername",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Errorf("exit_getpeername: got kind %d, want KindRet", r.Kind)
	}
}

// TestClassifyExitGetsockname locks in that the getsockname exit tracepoint is
// classified as KindRet. getsockname(2) returns int (0 on success, -1 on
// error), so its exit format carries a single "ret" field and must map to a
// plain ret_event, matching the generated sys_exit_getsockname handler — just
// like its sibling getpeername (see TestClassifyExitGetpeername).
func TestClassifyExitGetsockname(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_getsockname",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Errorf("exit_getsockname: got kind %d, want KindRet", r.Kind)
	}
}

// TestClassifySetsockoptEnterFd locks in that the setsockopt enter tracepoint is
// classified as KindFd with the socket fd captured at args[0]. The signature is:
//
//	int setsockopt(int sockfd, int level, int optname,
//	               const void *optval, socklen_t optlen)
//
// setsockopt(2) sets a socket option on the socket referred to by sockfd
// (args[0]); the remaining level/optname/optval/optlen args are NOT captured.
// optval is a userspace pointer (not a transferred byte buffer we account for),
// so only the leading sockfd matters — exactly like its KindFd network siblings
// bind/connect/getsockname/getpeername/getsockopt and the explicit name-only
// mapping in classify.go. The classification is name-only, so this asserts the
// kind holds even when the enter format carries the real "fd" field. Capturing
// any later arg as the fd, or failing to capture args[0], would be a real bug.
func TestClassifySetsockoptEnterFd(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_setsockopt",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "int", Name: "fd"},
			{Type: "int", Name: "level"},
			{Type: "int", Name: "optname"},
			{Type: "char *", Name: "optval"},
			{Type: "int", Name: "optlen"},
		},
	})
	if r.Kind != KindFd {
		t.Fatalf("enter_setsockopt: got kind %d, want KindFd", r.Kind)
	}
	// optval is a userspace pointer, never a pathname we record.
	if r.PathnameField != "" {
		t.Errorf("enter_setsockopt: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitSetsockoptUnclassifiedRet locks in that the setsockopt exit
// tracepoint is classified as KindRet and Unclassified. setsockopt(2) returns
// int (0 on success, -1 on error) — a status code, NOT a transferred byte count
// — so its exit format carries a single "ret" field and must map to a plain
// ret_event (KindRet) whose ret_type stays UNCLASSIFIED, matching the generated
// sys_exit_setsockopt handler and its sibling getsockopt. Misclassifying it as a
// READ/WRITE/TRANSFER byte count would be a real bug.
func TestClassifyExitSetsockoptUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_setsockopt",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_setsockopt: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_setsockopt"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_setsockopt) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifyExitGetsockoptUnclassifiedRet mirrors the setsockopt exit lock-in
// for its read-side sibling getsockopt(2), which likewise returns int (0/-1) and
// must map to a plain ret_event (KindRet, UNCLASSIFIED) — never a READ byte
// count, even though it copies option data into a userspace buffer via a
// userspace pointer rather than returning a transferred byte total.
func TestClassifyExitGetsockoptUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_getsockopt",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_getsockopt: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_getsockopt"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_getsockopt) = %q, want UNCLASSIFIED", got)
	}
}

func TestClassifySocket(t *testing.T) {
	r := classifyFromData(t, FormatSocket)
	if r.Kind != KindSocket {
		t.Errorf("socket: got kind %d, want KindSocket", r.Kind)
	}
}

func TestClassifySocketpair(t *testing.T) {
	r := classifyFromData(t, FormatSocketpair)
	if r.Kind != KindSocketpair {
		t.Errorf("socketpair: got kind %d, want KindSocketpair", r.Kind)
	}
}

func TestClassifyExitSocketpair(t *testing.T) {
	r := classifyFromData(t, FormatExitSocketpair)
	if r.Kind != KindSocketpair {
		t.Errorf("exit_socketpair: got kind %d, want KindSocketpair", r.Kind)
	}
}

// TestClassifySocketpairNotFd is a regression lock-in for the socketpair(2)
// audit (task c00). socketpair(int domain, int type, int protocol, int sv[2])
// takes the address-family/domain constant as args[0] (named "family" in the
// tracepoint format), NOT a file descriptor. The created fds are written into
// the OUTPUT array sv[2] (args[3]) and are only valid after the call returns.
// socketpair must therefore be KindSocketpair (read sv[2] at exit), never
// KindFd, which would record the domain integer as a bogus fd. Pin that the
// name-based override wins so a future field-shape change cannot make it fall
// through to the generic KindFd path.
func TestClassifySocketpairNotFd(t *testing.T) {
	r := classifyFromData(t, FormatSocketpair)
	if r.Kind == KindFd {
		t.Fatal("socketpair classified as KindFd: args[0] is the domain constant, not an fd")
	}
	if r.Kind != KindSocketpair {
		t.Errorf("socketpair: got kind %d, want KindSocketpair", r.Kind)
	}
}

func TestClassifyPipe(t *testing.T) {
	r := classifyFromData(t, FormatPipe)
	if r.Kind != KindPipe {
		t.Errorf("pipe: got kind %d, want KindPipe", r.Kind)
	}
}

func TestClassifyPipe2(t *testing.T) {
	r := classifyFromData(t, FormatPipe2)
	if r.Kind != KindPipe {
		t.Errorf("pipe2: got kind %d, want KindPipe", r.Kind)
	}
}

func TestClassifyExitPipe(t *testing.T) {
	r := classifyFromData(t, FormatExitPipe)
	if r.Kind != KindPipe {
		t.Errorf("exit_pipe: got kind %d, want KindPipe", r.Kind)
	}
}

func TestClassifyExitPipe2(t *testing.T) {
	r := classifyFromData(t, FormatExitPipe2)
	if r.Kind != KindPipe {
		t.Errorf("exit_pipe2: got kind %d, want KindPipe", r.Kind)
	}
}

// TestClassifyPipeNotFd locks in that pipe(2) is NOT classified as KindFd.
// pipe's args[0] is an OUTPUT pointer to int[2] (the two created fds are written
// there by the kernel and are only valid AFTER the syscall returns), NOT an fd
// argument. Capturing args[0] as an fd would attribute the pipe to a bogus
// descriptor; pipe must use the pipe-specific KindPipe path that reads the fd
// pair from the userspace buffer at exit. Same pitfall as socketpair (task c00).
func TestClassifyPipeNotFd(t *testing.T) {
	for _, name := range []string{"pipe", "pipe2"} {
		r := classifyFromData(t, map[string]string{
			"pipe":  FormatPipe,
			"pipe2": FormatPipe2,
		}[name])
		if r.Kind == KindFd {
			t.Fatalf("%s classified as KindFd: args[0] is an output ptr, not an fd", name)
		}
		if r.Kind != KindPipe {
			t.Errorf("%s: got kind %d, want KindPipe", name, r.Kind)
		}
	}
}

// TestClassifyPipeUnclassifiedRet locks in that the pipe and pipe2 exit
// tracepoints stay UNCLASSIFIED. pipe(2)/pipe2(2) return int (0 on success,
// -1 on error) — a status code, NOT a transferred byte count. They must not be
// in retClassifications and must never map to READ/WRITE/TRANSFER, which would
// misreport phantom bytes. The created fds are surfaced via fd0/fd1 in the
// pipe_event, not via the return value.
func TestClassifyPipeUnclassifiedRet(t *testing.T) {
	for _, name := range []string{"sys_exit_pipe", "sys_exit_pipe2"} {
		if got := ClassifyRet(name); got != Unclassified {
			t.Errorf("ClassifyRet(%s) = %q, want UNCLASSIFIED", name, got)
		}
	}
}

func TestClassifyEventfd(t *testing.T) {
	r := classifyFromData(t, FormatEventfd)
	if r.Kind != KindEventfd {
		t.Errorf("eventfd: got kind %d, want KindEventfd", r.Kind)
	}
}

func TestClassifyEventfd2(t *testing.T) {
	r := classifyFromData(t, FormatEventfd2)
	if r.Kind != KindEventfd {
		t.Errorf("eventfd2: got kind %d, want KindEventfd", r.Kind)
	}
}

func TestClassifyExitEventfd(t *testing.T) {
	r := classifyFromData(t, FormatExitEventfd)
	if r.Kind != KindEventfd {
		t.Errorf("exit_eventfd: got kind %d, want KindEventfd", r.Kind)
	}
}

func TestClassifyExitEventfd2(t *testing.T) {
	r := classifyFromData(t, FormatExitEventfd2)
	if r.Kind != KindEventfd {
		t.Errorf("exit_eventfd2: got kind %d, want KindEventfd", r.Kind)
	}
}

func TestClassifyEventfdSpecializedFdFromAirSyscalls(t *testing.T) {
	tests := []string{
		"sys_enter_memfd_create",
		"sys_exit_memfd_create",
		"sys_enter_memfd_secret",
		"sys_exit_memfd_secret",
		"sys_enter_userfaultfd",
		"sys_exit_userfaultfd",
		"sys_enter_signalfd",
		"sys_exit_signalfd",
		"sys_enter_signalfd4",
		"sys_exit_signalfd4",
		"sys_enter_timerfd_create",
		"sys_exit_timerfd_create",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r, ok := classifyNameOnly(name)
			if !ok {
				t.Fatalf("classifyNameOnly(%q) did not match", name)
			}
			if r.Kind != KindEventfd {
				t.Fatalf("classifyNameOnly(%q) kind = %v, want KindEventfd", name, r.Kind)
			}
		})
	}
}

func TestClassifyEpollCtl(t *testing.T) {
	r := classifyFromData(t, FormatEpollCtl)
	if r.Kind != KindEpollCtl {
		t.Errorf("epoll_ctl: got kind %d, want KindEpollCtl", r.Kind)
	}
}

func TestClassifyEpollWait(t *testing.T) {
	r := classifyFromData(t, FormatEpollWait)
	if r.Kind != KindFd {
		t.Errorf("epoll_wait: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyEpollPwait(t *testing.T) {
	r := classifyFromData(t, FormatEpollPwait)
	if r.Kind != KindFd {
		t.Errorf("epoll_pwait: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyEpollPwait2(t *testing.T) {
	r := classifyFromData(t, FormatEpollPwait2)
	if r.Kind != KindFd {
		t.Errorf("epoll_pwait2: got kind %d, want KindFd", r.Kind)
	}
}

func TestClassifyPoll(t *testing.T) {
	r := classifyFromData(t, FormatPoll)
	if r.Kind != KindPoll {
		t.Errorf("poll: got kind %d, want KindPoll", r.Kind)
	}
}

func TestClassifyPpoll(t *testing.T) {
	r := classifyFromData(t, FormatPpoll)
	if r.Kind != KindPoll {
		t.Errorf("ppoll: got kind %d, want KindPoll", r.Kind)
	}
}

func TestClassifySelect(t *testing.T) {
	r := classifyFromData(t, FormatSelect)
	if r.Kind != KindPoll {
		t.Errorf("select: got kind %d, want KindPoll", r.Kind)
	}
}

func TestClassifyPselect6(t *testing.T) {
	r := classifyFromData(t, FormatPselect6)
	if r.Kind != KindPoll {
		t.Errorf("pselect6: got kind %d, want KindPoll", r.Kind)
	}
}

func TestClassifyMunmap(t *testing.T) {
	r := classifyFromData(t, FormatMunmap)
	if r.Kind != KindMem {
		t.Errorf("munmap: got kind %d, want KindMem", r.Kind)
	}
}

func TestClassifyMremap(t *testing.T) {
	r := classifyFromData(t, FormatMremap)
	if r.Kind != KindMem {
		t.Errorf("mremap: got kind %d, want KindMem", r.Kind)
	}
}

func TestClassifyNanosleep(t *testing.T) {
	r := classifyFromData(t, FormatNanosleep)
	if r.Kind != KindSleep {
		t.Errorf("nanosleep: got kind %d, want KindSleep", r.Kind)
	}
}

func TestClassifyClockNanosleep(t *testing.T) {
	r := classifyFromData(t, FormatClockNanosleep)
	if r.Kind != KindSleep {
		t.Errorf("clock_nanosleep: got kind %d, want KindSleep", r.Kind)
	}
}

func TestClassifyKeyctl(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_keyctl",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "int", Name: "option"},
			{Type: "key_serial_t", Name: "arg2"},
		},
	})
	if r.Kind != KindKeyctl {
		t.Errorf("keyctl: got kind %d, want KindKeyctl", r.Kind)
	}
}

func TestClassifyAddKey(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_add_key",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "_type"},
			{Type: "const char *", Name: "_description"},
			{Type: "const void *", Name: "_payload"},
			{Type: "size_t", Name: "plen"},
			{Type: "key_serial_t", Name: "ringid"},
		},
	})
	if r.Kind != KindKeyctl {
		t.Errorf("add_key: got kind %d, want KindKeyctl", r.Kind)
	}
}

// TestClassifyRequestKey locks in the request_key(2) classification:
//
//	key_serial_t request_key(const char *type, const char *description,
//	                         const char *callout_info, key_serial_t dest_keyring)
//
// type/description/callout_info are key metadata STRINGS (a key type name, a
// free-form description and optional callout payload), NOT filesystem paths,
// so the const char * args must not trip the pathname/open heuristics. The
// name-only table maps request_key to KindKeyctl before any field is
// inspected; the generated handler captures only the numeric dest_keyring
// (args[3]) plus the option=-2 sentinel, and the exit returns a key serial /
// -1 that is not a byte count (UNCLASSIFIED).
func TestClassifyRequestKey(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_request_key",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "_type"},
			{Type: "const char *", Name: "_description"},
			{Type: "const char *", Name: "_callout_info"},
			{Type: "key_serial_t", Name: "destringid"},
		},
	})
	if r.Kind != KindKeyctl {
		t.Errorf("request_key: got kind %d, want KindKeyctl", r.Kind)
	}
	// The const char * type/description/callout_info args are key metadata,
	// not paths — no path capture must be emitted for them.
	if r.PathnameField != "" {
		t.Errorf("request_key: got PathnameField %q, want empty (string args are key metadata, not paths)", r.PathnameField)
	}
	// Family: Security, alongside add_key/keyctl/lsm_*/seccomp siblings.
	for _, prefix := range []string{"sys_enter_", "sys_exit_"} {
		if fam := ClassifySyscallFamily(prefix + "request_key"); fam != FamilySecurity {
			t.Errorf("%srequest_key: got family %s, want FamilySecurity", prefix, fam)
		}
	}
	// Return value is a key serial / -1, never a byte transfer.
	if got := ClassifyRet("sys_exit_request_key"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_request_key) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifyKeyctlAudit is a lock-in regression test for the keyctl(2)
// audit. The key-management syscalls have these signatures:
//
//	long         keyctl(int op, unsigned long arg2, arg3, arg4, arg5)
//	key_serial_t add_key(const char *type, const char *desc,
//	                     const void *payload, size_t plen, key_serial_t keyring)
//	key_serial_t request_key(const char *type, const char *desc,
//	                     const char *callout_info, key_serial_t dest_keyring)
//
// keyctl's op selects a command and the remaining arguments are
// operation-dependent unsigned longs — never an fd or a path. add_key and
// request_key take string TYPE/DESCRIPTION arguments that are key metadata
// (a key type name and a free-form description), NOT filesystem paths, so
// they must not be classified as KindPathname/KindOpen. All three therefore
// classify as KindKeyctl (operation + generic numeric args, captured via the
// keyctl_event without any bpf_probe_read_user path/fd capture), live in the
// FamilySecurity family alongside their *_key/landlock_*/lsm_*/seccomp
// siblings, and return an operation-dependent value or -1 that is NOT a byte
// transfer, so their exits stay UNCLASSIFIED.
func TestClassifyKeyctlAudit(t *testing.T) {
	for _, name := range []string{"keyctl", "add_key", "request_key"} {
		// Family: Security on both enter and exit tracepoint names.
		for _, prefix := range []string{"sys_enter_", "sys_exit_"} {
			if fam := ClassifySyscallFamily(prefix + name); fam != FamilySecurity {
				t.Errorf("%s%s: got family %s, want FamilySecurity", prefix, name, fam)
			}
		}

		// Returns: UNCLASSIFIED (key serial / op-dependent value / -1, not
		// a byte count), so the exit must NOT be tagged as a read/write/
		// transfer byte transfer.
		if got := ClassifyRet("sys_exit_" + name); got != Unclassified {
			t.Errorf("ClassifyRet(sys_exit_%s) = %q, want UNCLASSIFIED", name, got)
		}
	}

	// Contrast: add_key/request_key take a const char * "type"/"description"
	// first argument, but it is key metadata, not a path. Such a field name
	// must NOT trip the generic pathname/open heuristics — the name-only table
	// maps these syscalls to KindKeyctl before any field is inspected.
	addKey := ClassifyFormat(&Format{
		Name: "sys_enter_add_key",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "_type"},
			{Type: "const char *", Name: "_description"},
			{Type: "const void *", Name: "_payload"},
			{Type: "size_t", Name: "plen"},
			{Type: "key_serial_t", Name: "ringid"},
		},
	})
	if addKey.Kind != KindKeyctl {
		t.Errorf("add_key: got kind %d, want KindKeyctl (string args are key metadata, not paths)", addKey.Kind)
	}
	if addKey.PathnameField != "" {
		t.Errorf("add_key: got PathnameField %q, want empty (no path capture)", addKey.PathnameField)
	}
}

func TestClassifyPtrace(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_ptrace",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "request"},
			{Type: "long", Name: "pid"},
		},
	})
	if r.Kind != KindPtrace {
		t.Errorf("ptrace: got kind %d, want KindPtrace", r.Kind)
	}
}

func TestClassifyPerfEventOpen(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_perf_event_open",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "struct perf_event_attr *", Name: "attr_uptr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "int", Name: "cpu"},
			{Type: "int", Name: "group_fd"},
			{Type: "unsigned long", Name: "flags"},
		},
	})
	if r.Kind != KindPerfOpen {
		t.Errorf("perf_event_open: got kind %d, want KindPerfOpen", r.Kind)
	}
}

func TestClassifyMqOpen(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_mq_open",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "u_name"},
			{Type: "int", Name: "oflag"},
		},
	})
	if r.Kind != KindMqOpen {
		t.Errorf("mq_open: got kind %d, want KindMqOpen", r.Kind)
	}
}

func TestClassifyMqUnlink(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_mq_unlink",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "u_name"},
		},
	})
	if r.Kind != KindPathname {
		t.Errorf("mq_unlink: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "u_name" {
		t.Errorf("mq_unlink: PathnameField = %q, want u_name", r.PathnameField)
	}
}

func TestClassifyMqFdSyscallsByName(t *testing.T) {
	tests := []string{
		"mq_timedsend",
		"mq_timedreceive",
		"mq_notify",
		"mq_getsetattr",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: "sys_enter_" + name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "mqd_t", Name: "mqdes"},
				},
			})
			if r.Kind != KindFd {
				t.Errorf("%s: got kind %d, want KindFd", name, r.Kind)
			}
		})
	}
}

func TestClassifyN7NameOnlyKinds(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_pidfd_open", KindPidfd},
		{"sys_exit_pidfd_open", KindPidfd},
		{"sys_enter_pidfd_send_signal", KindFd},
		{"sys_enter_kexec_file_load", KindFd},
		{"sys_enter_kcmp", KindTwoFd},
		{"sys_enter_membarrier", KindNull},
		{"sys_enter_rseq", KindNull},
		{"sys_enter_set_robust_list", KindNull},
		{"sys_enter_get_robust_list", KindNull},
		{"sys_enter_mmap2", KindNull},
		{"sys_enter_kexec_load", KindNull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: tt.name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != tt.want {
				t.Fatalf("%s: got kind %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

// TestClassifySendfile64CapturesOutFd locks in the sendfile64 audit (task az):
// sendfile64(out_fd, in_fd, offset, count) transfers bytes between two file
// descriptors inside the kernel and returns the count written to out_fd. Its
// real tracepoint fields carry no field literally named "fd", so without the
// explicit nameOnlyKindsTable override it would fall through to KindNull and
// capture no descriptor — inconsistent with its sibling copy_file_range (KindFd)
// and the read/write/sendto/recvfrom families. This test pins that sendfile64 is
// a KindFd event capturing out_fd (args[0], the write destination) and that the
// generated C emits exactly that capture, never a null_event.
func TestClassifySendfile64CapturesOutFd(t *testing.T) {
	// Realistic enter layout from /sys/kernel/tracing for sys_enter_sendfile64.
	enter := &Format{
		Name: "sys_enter_sendfile64",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "int", Name: "out_fd"},
			{Type: "int", Name: "in_fd"},
			{Type: "off_t *", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
	}
	r := ClassifyFormat(enter)
	if r.Kind != KindFd {
		t.Fatalf("sendfile64: got kind %d, want KindFd (must not fall back to KindNull)", r.Kind)
	}
	// Negative guard: out_fd/in_fd must not be mistaken for a two-fd event; the
	// audit deliberately keeps sendfile64 single-fd like copy_file_range.
	if r.Kind == KindTwoFd || r.Kind == KindNull {
		t.Fatalf("sendfile64: kind %d, want single-fd KindFd, not two-fd/null", r.Kind)
	}

	// Generated C must capture out_fd at args[0] (the byte-write destination) via
	// a struct fd_event, never a struct null_event.
	output := GenerateTracepointsC(phaseAFormats("sendfile64", 9500))
	if !strings.Contains(output, "/// sys_enter_sendfile64 is a struct fd_event") {
		t.Fatalf("sys_enter_sendfile64 should be a struct fd_event:\n%s", output)
	}
	if strings.Contains(output, "/// sys_enter_sendfile64 is a struct null_event") {
		t.Fatalf("sys_enter_sendfile64 must not be a struct null_event:\n%s", output)
	}
	if !strings.Contains(output, "ev->fd = (__s32)ctx->args[0];") {
		t.Fatalf("sys_enter_sendfile64 should capture out_fd from args[0]:\n%s", output)
	}
	// Return value stays TransferClassified: sendfile64 moves bytes between two
	// fds, consistent with copy_file_range/splice/tee/vmsplice.
	if c := ClassifyRet("sys_exit_sendfile64"); c != TransferClassified {
		t.Fatalf("sendfile64 ret: got %v, want TransferClassified", c)
	}
}

func TestClassifyG7NameOnlyKinds(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_epoll_create", KindEventfd},
		{"sys_exit_epoll_create", KindEventfd},
		{"sys_enter_epoll_create1", KindEventfd},
		{"sys_exit_epoll_create1", KindEventfd},
		{"sys_enter_inotify_init", KindEventfd},
		{"sys_exit_inotify_init", KindEventfd},
		{"sys_enter_inotify_init1", KindEventfd},
		{"sys_exit_inotify_init1", KindEventfd},
		{"sys_enter_fanotify_init", KindEventfd},
		{"sys_exit_fanotify_init", KindEventfd},
		{"sys_enter_landlock_create_ruleset", KindEventfd},
		{"sys_exit_landlock_create_ruleset", KindEventfd},
		{"sys_enter_fsopen", KindEventfd},
		{"sys_exit_fsopen", KindEventfd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: tt.name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != tt.want {
				t.Fatalf("%s: got kind %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

func TestClassifyI7NameOnlyKinds(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_mincore", KindMem},
		{"sys_enter_remap_file_pages", KindMem},
		{"sys_enter_mlock", KindMem},
		{"sys_enter_mlock2", KindMem},
		{"sys_enter_munlock", KindMem},
		{"sys_enter_mseal", KindMem},
		{"sys_enter_map_shadow_stack", KindMem},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: tt.name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != tt.want {
				t.Fatalf("%s: got kind %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

func TestClassifyH7NameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_mprotect",
		"sys_enter_madvise",
		"sys_enter_pkey_mprotect",
		"sys_enter_brk",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindMem {
				t.Fatalf("%s: got kind %d, want KindMem", name, r.Kind)
			}
		})
	}
}

func TestClassifyL7NameOnlyKinds(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_pkey_alloc", KindNull},
		{"sys_enter_pkey_free", KindNull},
		{"sys_enter_mbind", KindNull},
		{"sys_enter_set_mempolicy", KindNull},
		{"sys_enter_get_mempolicy", KindNull},
		{"sys_enter_set_mempolicy_home_node", KindNull},
		{"sys_enter_migrate_pages", KindNull},
		{"sys_enter_move_pages", KindNull},
		{"sys_enter_mlockall", KindNull},
		{"sys_enter_munlockall", KindNull},
		{"sys_enter_process_madvise", KindFd},
		{"sys_enter_process_mrelease", KindFd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: tt.name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != tt.want {
				t.Fatalf("%s: got kind %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

func TestClassifyJ7NameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_futex",
		"sys_enter_futex_wait",
		"sys_enter_futex_wake",
		"sys_enter_futex_requeue",
		"sys_enter_futex_waitv",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindFutex {
				t.Fatalf("%s: got kind %d, want KindFutex", name, r.Kind)
			}
		})
	}
}

func TestClassifyK7NameOnlyKinds(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_wait4", KindProc},
		{"sys_enter_waitid", KindProc},
		{"sys_enter_kill", KindNull},
		{"sys_enter_prctl", KindPrctl},
		{"sys_enter_setns", KindFd},
		{"sys_enter_unshare", KindNull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: tt.name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != tt.want {
				t.Fatalf("%s: got kind %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

func TestClassifyM7NameOnlyKinds(t *testing.T) {
	nullKinds := []string{
		"sys_enter_clock_gettime",
		"sys_enter_clock_settime",
		"sys_enter_clock_getres",
		"sys_enter_clock_adjtime",
		"sys_enter_gettimeofday",
		"sys_enter_settimeofday",
		"sys_enter_time",
		"sys_enter_times",
		"sys_enter_adjtimex",
		"sys_enter_alarm",
		"sys_enter_getitimer",
		"sys_enter_setitimer",
	}
	for _, name := range nullKinds {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindNull {
				t.Fatalf("%s: got kind %d, want KindNull", name, r.Kind)
			}
		})
	}

	timerObjKinds := []string{
		"sys_enter_timer_create",
		"sys_enter_timer_settime",
		"sys_enter_timer_gettime",
		"sys_enter_timer_getoverrun",
		"sys_enter_timer_delete",
	}
	for _, name := range timerObjKinds {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindTimerObj {
				t.Fatalf("%s: got kind %d, want KindTimerObj", name, r.Kind)
			}
		})
	}
}

func TestClassifyO7NameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_landlock_add_rule",
		"sys_enter_landlock_restrict_self",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindFd {
				t.Fatalf("%s: got kind %d, want KindFd", name, r.Kind)
			}
		})
	}
}

func TestClassify67NameOnlyKinds(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_seccomp", KindSeccomp},
		{"sys_exit_seccomp", KindSeccomp},
		{"sys_enter_init_module", KindModule},
		{"sys_exit_init_module", KindModule},
		{"sys_enter_delete_module", KindModule},
		{"sys_exit_delete_module", KindModule},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: tt.name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != tt.want {
				t.Fatalf("%s: got kind %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

// TestClassifyInitModuleVsFinitModule locks in the load-bearing distinction
// between the two module-loading syscalls (man 2 init_module).
//
// init_module(void *module_image, unsigned long len, const char *param_values)
// takes a userspace ELF image pointer and a module-PARAMETER string (not a
// filesystem path), so it must classify as KindModule (null_event) and capture
// neither an fd nor a path — param_values must NOT be mistaken for a path.
//
// finit_module(int fd, const char *param_values, int flags) reads the module
// from a file descriptor, so it must classify as KindFd via field-based
// matching on the leading "fd" field.
func TestClassifyInitModuleVsFinitModule(t *testing.T) {
	if r := classifyFromData(t, FormatInitModule); r.Kind != KindModule {
		t.Errorf("init_module: got kind %d, want KindModule", r.Kind)
	}
	if r := classifyFromData(t, FormatFinitModule); r.Kind != KindFd {
		t.Errorf("finit_module: got kind %d, want KindFd", r.Kind)
	}

	// param_values (uargs) is a parameter string, never a captured path: the
	// init_module classification must not select KindPathname/KindName/KindOpen.
	if r := classifyFromData(t, FormatInitModule); r.PathnameField != "" {
		t.Errorf("init_module: unexpected PathnameField %q, want empty", r.PathnameField)
	}
	if r := classifyFromData(t, FormatFinitModule); r.PathnameField != "" {
		t.Errorf("finit_module: unexpected PathnameField %q, want empty", r.PathnameField)
	}

	// Both module-loading syscalls live in FamilySecurity (man 2 init_module:
	// loading kernel code is a privileged, security-sensitive operation), and
	// both return 0/-1 with no byte count, so their exits are UNCLASSIFIED.
	for _, name := range []string{"init_module", "finit_module"} {
		if fam := ClassifySyscallFamily("sys_enter_" + name); fam != FamilySecurity {
			t.Errorf("%s: got family %s, want FamilySecurity", name, fam)
		}
		if got := ClassifyRet("sys_exit_" + name); got != Unclassified {
			t.Errorf("ClassifyRet(sys_exit_%s) = %q, want UNCLASSIFIED", name, got)
		}
	}
}

func TestClassify87NameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_rt_sigaction",
		"sys_enter_rt_sigprocmask",
		"sys_enter_rt_sigpending",
		"sys_enter_rt_sigsuspend",
		"sys_enter_rt_sigtimedwait",
		"sys_enter_rt_sigreturn",
		"sys_enter_sigaltstack",
		"sys_enter_pause",
		"sys_enter_rt_sigqueueinfo",
		"sys_enter_rt_tgsigqueueinfo",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindNull {
				t.Fatalf("%s: got kind %d, want KindNull", name, r.Kind)
			}
		})
	}
}

func TestClassify97NameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_getpid",
		"sys_enter_gettid",
		"sys_enter_getppid",
		"sys_enter_getuid",
		"sys_enter_geteuid",
		"sys_enter_getgid",
		"sys_enter_getegid",
		"sys_enter_getresuid",
		"sys_enter_getresgid",
		"sys_enter_getgroups",
		"sys_enter_setuid",
		"sys_enter_seteuid",
		"sys_enter_setgid",
		"sys_enter_setegid",
		"sys_enter_setresuid",
		"sys_enter_setresgid",
		"sys_enter_setreuid",
		"sys_enter_setregid",
		"sys_enter_setfsuid",
		"sys_enter_setfsgid",
		"sys_enter_setgroups",
		"sys_enter_umask",
		"sys_enter_setsid",
		"sys_enter_getsid",
		"sys_enter_setpgid",
		"sys_enter_getpgid",
		"sys_enter_getpgrp",
		"sys_enter_set_tid_address",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindNull {
				t.Fatalf("%s: got kind %d, want KindNull", name, r.Kind)
			}
		})
	}
}

func TestClassifyA7NameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_sched_yield",
		"sys_enter_sched_setaffinity",
		"sys_enter_sched_getaffinity",
		"sys_enter_sched_setparam",
		"sys_enter_sched_getparam",
		"sys_enter_sched_setscheduler",
		"sys_enter_sched_getscheduler",
		"sys_enter_sched_setattr",
		"sys_enter_sched_getattr",
		"sys_enter_sched_get_priority_max",
		"sys_enter_sched_get_priority_min",
		"sys_enter_sched_rr_get_interval",
		"sys_enter_getcpu",
		"sys_enter_getrusage",
		"sys_enter_getrlimit",
		"sys_enter_setrlimit",
		"sys_enter_prlimit64",
		"sys_enter_getpriority",
		"sys_enter_setpriority",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindNull {
				t.Fatalf("%s: got kind %d, want KindNull", name, r.Kind)
			}
		})
	}
}

func TestClassifyE7NullNameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_sysinfo",
		"sys_enter_sysfs",
		"sys_enter_ustat",
		"sys_enter_newuname",
		"sys_enter_sethostname",
		"sys_enter_setdomainname",
		"sys_enter_capget",
		"sys_enter_capset",
		"sys_enter_personality",
		"sys_enter_reboot",
		"sys_enter_restart_syscall",
		"sys_enter_vhangup",
		"sys_enter_arch_prctl",
		"sys_enter_ioperm",
		"sys_enter_iopl",
		"sys_enter_modify_ldt",
		"sys_enter_lsm_get_self_attr",
		"sys_enter_lsm_set_self_attr",
		"sys_enter_lsm_list_modules",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindNull {
				t.Fatalf("%s: got kind %d, want KindNull", name, r.Kind)
			}
		})
	}
}

// TestClassifyIoplNullEnter locks in the iopl(2) enter classification using the
// syscall's REAL tracepoint field. iopl(int level) changes the x86 I/O privilege
// level of the calling thread (the two least significant bits of level select
// the IOPL, 0-3); level is a plain int status/selector, NOT a file descriptor and
// NOT a filesystem path. iopl is in nameOnlyKindsTable, so its enter classifies
// as KindNull by name before any field heuristic runs — but the audit concern is
// that the single "level" int must never be captured as an fd or a path. Using
// the real "int level" field here (rather than the synthetic arg0 used by
// TestClassifyE7NullNameOnlyKinds) proves the heuristics would not capture it
// even if the name-only mapping were removed: the fd heuristic requires the field
// be named "fd" (which "level" is not), and no string-pointer path field exists.
// Siblings ioperm/modify_ldt share this null_event shape (FamilyMisc, asserted in
// family_test.go).
func TestClassifyIoplNullEnter(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_iopl",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "int", Name: "level"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("enter_iopl: got kind %d, want KindNull", r.Kind)
	}
	// The "level" argument must not be captured as a file descriptor or path.
	if r.PathnameField != "" {
		t.Errorf("enter_iopl: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitIoplUnclassifiedRet locks in that the iopl exit tracepoint is
// classified as KindRet and Unclassified. iopl(2) returns int (0 on success, -1
// on error) — a status code, NOT a transferred byte count — so its exit format
// carries a single "ret" field and must map to a plain ret_event (KindRet) whose
// ret_type stays UNCLASSIFIED (matching the generated handle_sys_exit_iopl).
// Misclassifying that status as a READ/WRITE/TRANSFER byte count would be a real
// bug; it shares this shape with its siblings ioperm/modify_ldt.
func TestClassifyExitIoplUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_iopl",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_iopl: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_iopl"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_iopl) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifyArchPrctlNullEnter locks in the arch_prctl(2) enter classification
// using the syscall's REAL kernel tracepoint fields. arch_prctl(int op, unsigned
// long addr) sets/gets x86-64-specific thread state (ARCH_SET_FS, ARCH_GET_FS,
// ARCH_SET_GS, ARCH_GET_GS, ARCH_SET_CPUID, ARCH_GET_CPUID). The kernel exposes
// these args as "option" (an int operation code) and "arg2" (an unsigned long
// that is either a value for the SET ops or a userspace pointer for the GET ops).
// Neither is a file descriptor and neither is a filesystem path. arch_prctl is in
// nameOnlyKindsTable, so its enter classifies as KindNull by name before any field
// heuristic runs — but the audit concern is that "option"/"arg2" must never be
// captured as an fd or a path. Using the real fields here (rather than the
// synthetic arg0 used by TestClassifyE7NullNameOnlyKinds) proves the heuristics
// would not capture them even if the name-only mapping were removed: the fd
// heuristic requires a field named "fd" (neither "option" nor "arg2" qualifies),
// and no C-string-pointer path field exists. arch_prctl is deliberately
// FamilyProcess (asserted in family_test.go), not Misc, unlike its x86 siblings
// ioperm/iopl/modify_ldt.
func TestClassifyArchPrctlNullEnter(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_arch_prctl",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "int", Name: "option"},
			{Type: "unsigned long", Name: "arg2"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("enter_arch_prctl: got kind %d, want KindNull", r.Kind)
	}
	// Neither the "option" code nor the "arg2" value/pointer must be captured as a
	// file descriptor or a path.
	if r.PathnameField != "" {
		t.Errorf("enter_arch_prctl: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitArchPrctlUnclassifiedRet locks in that the arch_prctl exit
// tracepoint is classified as KindRet and Unclassified. arch_prctl(2) returns int
// (0 on success, -1 on error) — a status code, NOT a transferred byte count — so
// its exit format carries a single "ret" field and must map to a plain ret_event
// (KindRet) whose ret_type stays UNCLASSIFIED (matching the generated
// handle_sys_exit_arch_prctl). Misclassifying that status as a READ/WRITE/TRANSFER
// byte count would be a real bug. (The ARCH_GET_CPUID op returns the flag setting
// in the return value, but it is still a small status code, not an I/O byte
// count.)
func TestClassifyExitArchPrctlUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_arch_prctl",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_arch_prctl: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_arch_prctl"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_arch_prctl) = %q, want UNCLASSIFIED", got)
	}
}

// TestClassifyIoprioNullKind locks in the argument-capture classification for
// ioprio_set/ioprio_get using their real kernel tracepoint fields. Unlike the
// name-only Misc/null syscalls above, ioprio_* are NOT in nameOnlyKindsTable:
// they classify by field fallthrough. ioprio_set(which, who, ioprio) and
// ioprio_get(which, who) carry only int-typed which/who/ioprio fields. None is
// named "fd"/"pathname"/"path"/"filename", so ClassifyFormat must return
// KindNone — in particular the "who" argument (a pid/pgid/uid selected by
// "which", never an fd) must NOT be misclassified as KindFd, and nothing must be
// captured as a path. classifyEnterForGeneration then promotes the field-bearing
// enter format to KindNull (the null_event seen in generated_tracepoints.c).
func TestClassifyIoprioNullKind(t *testing.T) {
	cases := []struct {
		name   string
		fields []Field
	}{
		{
			name: "sys_enter_ioprio_set",
			fields: []Field{
				{Type: "int", Name: "__syscall_nr"},
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
				{Type: "int", Name: "ioprio"},
			},
		},
		{
			name: "sys_enter_ioprio_get",
			fields: []Field{
				{Type: "int", Name: "__syscall_nr"},
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Format{Name: tc.name, ExternalFields: tc.fields}

			// No field should match an fd/path/name pattern: raw classification
			// is KindNone, proving "who" is not captured as an fd.
			if r := ClassifyFormat(f); r.Kind != KindNone {
				t.Fatalf("%s: ClassifyFormat kind = %d, want KindNone", tc.name, r.Kind)
			}

			// The generator promotes the field-bearing enter format to KindNull.
			if r := classifyEnterForGeneration(f); r.Kind != KindNull {
				t.Fatalf("%s: classifyEnterForGeneration kind = %d, want KindNull", tc.name, r.Kind)
			}
		})
	}
}

func TestClassifyB7NameOnlyKinds(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_msgget", KindSysVId},
		{"sys_enter_semget", KindSysVId},
		{"sys_enter_shmget", KindSysVId},
		{"sys_enter_msgsnd", KindSysVOp},
		{"sys_enter_msgrcv", KindSysVOp},
		{"sys_enter_msgctl", KindSysVOp},
		{"sys_enter_semop", KindSysVOp},
		{"sys_enter_semtimedop", KindSysVOp},
		{"sys_enter_semctl", KindSysVOp},
		{"sys_enter_shmat", KindSysVOp},
		{"sys_enter_shmdt", KindSysVOp},
		{"sys_enter_shmctl", KindSysVOp},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: tt.name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != tt.want {
				t.Fatalf("%s: got kind %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

func TestClassify37NameOnlyKinds(t *testing.T) {
	tests := []string{
		"sys_enter_clone",
		"sys_enter_clone3",
		"sys_enter_fork",
		"sys_enter_vfork",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "long", Name: "arg0"},
				},
			})
			if r.Kind != KindProc {
				t.Fatalf("%s: got kind %d, want KindProc", name, r.Kind)
			}
		})
	}
}

func TestClassify57NameOnlyKinds(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_bpf",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "int", Name: "cmd"},
			{Type: "union bpf_attr *", Name: "attr"},
			{Type: "unsigned int", Name: "size"},
		},
	})
	if r.Kind != KindBpf {
		t.Fatalf("sys_enter_bpf: got kind %d, want KindBpf", r.Kind)
	}
}

func TestClassifyAcctPathname(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_enter_acct",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "name"},
		},
	})
	if r.Kind != KindPathname {
		t.Fatalf("acct: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "name" {
		t.Fatalf("acct: PathnameField=%q, want name", r.PathnameField)
	}
}

// TestClassifySetdomainnameNotPath locks in the audit finding for the
// setdomainname(2) syscall (`int setdomainname(const char *name, size_t len)`).
// Its first arg is a `const char *name`, but that name is the NIS/YP domain
// name string — NOT a filesystem path. The name-only table therefore pins it to
// KindNull so the field-based path heuristic (which would otherwise treat a
// `const char *name` arg as KindPathname) never fires. The sibling sethostname
// must classify identically, and both must share a family, so the two stay
// consistent.
func TestClassifySetdomainnameNotPath(t *testing.T) {
	// Realistic format including the const char *name arg that the path
	// heuristic would latch onto if the name-only table did not win first.
	setdomainname := ClassifyFormat(&Format{
		Name: "sys_enter_setdomainname",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
	})
	if setdomainname.Kind != KindNull {
		t.Fatalf("setdomainname: got kind %d, want KindNull (domain name is not a path)", setdomainname.Kind)
	}
	if setdomainname.PathnameField != "" {
		t.Fatalf("setdomainname: PathnameField=%q, want empty (must not be captured as a path)", setdomainname.PathnameField)
	}

	sethostname := ClassifyFormat(&Format{
		Name: "sys_enter_sethostname",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "const char *", Name: "name"},
			{Type: "size_t", Name: "len"},
		},
	})
	if sethostname.Kind != setdomainname.Kind {
		t.Fatalf("sethostname kind %d != setdomainname kind %d: siblings must agree", sethostname.Kind, setdomainname.Kind)
	}

	if got := ClassifySyscallFamily("sys_enter_setdomainname"); got != FamilyMisc {
		t.Fatalf("setdomainname: family=%q, want %q", got, FamilyMisc)
	}
	if got, want := ClassifySyscallFamily("sys_enter_setdomainname"), ClassifySyscallFamily("sys_enter_sethostname"); got != want {
		t.Fatalf("setdomainname family %q != sethostname family %q: siblings must agree", got, want)
	}
}

func TestClassifyMount(t *testing.T) {
	r := classifyFromData(t, FormatMount)
	if r.Kind != KindPathname {
		t.Errorf("mount: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "dir_name" {
		t.Errorf("mount: PathnameField = %q, want dir_name", r.PathnameField)
	}
}

func TestClassifyUmount(t *testing.T) {
	r := classifyFromData(t, FormatUmount)
	if r.Kind != KindPathname {
		t.Errorf("umount: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "name" {
		t.Errorf("umount: PathnameField = %q, want name", r.PathnameField)
	}
}

func TestClassifyMoveMount(t *testing.T) {
	r := classifyFromData(t, FormatMoveMount)
	if r.Kind != KindTwoFd {
		t.Errorf("move_mount: got kind %d, want KindTwoFd", r.Kind)
	}
}

func TestClassifyFsmount(t *testing.T) {
	r := classifyFromData(t, FormatFsmount)
	if r.Kind != KindEventfd {
		t.Errorf("fsmount: got kind %d, want KindEventfd", r.Kind)
	}
}

func TestClassifyExitFsmount(t *testing.T) {
	r := classifyFromData(t, FormatExitFsmount)
	if r.Kind != KindEventfd {
		t.Errorf("exit_fsmount: got kind %d, want KindEventfd", r.Kind)
	}
}

func TestClassifyPivotRoot(t *testing.T) {
	r := classifyFromData(t, FormatPivotRoot)
	if r.Kind != KindPathname {
		t.Errorf("pivot_root: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "new_root" {
		t.Errorf("pivot_root: PathnameField = %q, want new_root", r.PathnameField)
	}
}

func TestClassifyQuotactl(t *testing.T) {
	r := classifyFromData(t, FormatQuotactl)
	if r.Kind != KindPathname {
		t.Errorf("quotactl: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "special" {
		t.Errorf("quotactl: PathnameField = %q, want special", r.PathnameField)
	}
}

func TestClassifyStatmount(t *testing.T) {
	r := classifyFromData(t, FormatStatmount)
	if r.Kind != KindNull {
		t.Errorf("statmount: got kind %d, want KindNull", r.Kind)
	}
}

func TestClassifyListmount(t *testing.T) {
	r := classifyFromData(t, FormatListmount)
	if r.Kind != KindNull {
		t.Errorf("listmount: got kind %d, want KindNull", r.Kind)
	}
}

func TestClassifyListns(t *testing.T) {
	r := classifyFromData(t, FormatListns)
	if r.Kind != KindNull {
		t.Errorf("listns: got kind %d, want KindNull", r.Kind)
	}
}

func TestClassifySwapon(t *testing.T) {
	r := classifyFromData(t, FormatSwapon)
	if r.Kind != KindPathname {
		t.Errorf("swapon: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "specialfile" {
		t.Errorf("swapon: PathnameField = %q, want specialfile", r.PathnameField)
	}
}

func TestClassifySwapoff(t *testing.T) {
	r := classifyFromData(t, FormatSwapoff)
	if r.Kind != KindPathname {
		t.Errorf("swapoff: got kind %d, want KindPathname", r.Kind)
	}
	if r.PathnameField != "specialfile" {
		t.Errorf("swapoff: PathnameField = %q, want specialfile", r.PathnameField)
	}
}

// TestClassifyKillExplicitNull locks in the kill(2) enter classification using
// the syscall's REAL tracepoint fields. kill(pid_t pid, int sig) sends signal
// sig to a process (or process group); both arguments are integers — a process/
// process-group identifier and a signal number — NOT a file descriptor and NOT
// a filesystem path. The audit concern is that args[0] ("pid") could be mistaken
// for an fd: it must not be. kill has no fd or path argument, so its enter format
// must classify as KindNull (null_event), matching its signal siblings tkill/
// tgkill/rt_sigqueueinfo and the explicit name-only mapping in classify.go.
// (Its pidfd-taking sibling pidfd_send_signal differs deliberately: args[0]
// there is a real pidfd file descriptor, so that one is KindFd/FamilyIPC.)
func TestClassifyKillExplicitNull(t *testing.T) {
	r := classifyFromData(t, FormatKill)
	if r.Kind != KindNull {
		t.Errorf("kill: got kind %d, want KindNull", r.Kind)
	}
	// Neither the pid nor the sig argument must be captured as a path/fd.
	if r.PathnameField != "" {
		t.Errorf("kill: unexpected PathnameField %q, want empty", r.PathnameField)
	}
}

// TestClassifyExitKillUnclassifiedRet locks in that the kill exit tracepoint is
// classified as KindRet and Unclassified. kill(2) returns int (0 on success, -1
// on error) — that return is a status code, NOT a transferred byte count — so
// its exit format carries a single "ret" field and must map to a plain ret_event
// (KindRet) whose ret_type stays UNCLASSIFIED. This matches its signal siblings
// (tkill/tgkill/rt_sigqueueinfo); misclassifying it as a READ/WRITE/TRANSFER
// byte count would be a real bug.
func TestClassifyExitKillUnclassifiedRet(t *testing.T) {
	r := ClassifyFormat(&Format{
		Name: "sys_exit_kill",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if r.Kind != KindRet {
		t.Fatalf("exit_kill: got kind %d, want KindRet", r.Kind)
	}
	if got := ClassifyRet("sys_exit_kill"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_kill) = %q, want UNCLASSIFIED", got)
	}
}

func TestClassifyNullExitByName(t *testing.T) {
	tests := []string{"sys_enter_exit", "sys_enter_exit_group"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			r := ClassifyFormat(&Format{
				Name: name,
				ExternalFields: []Field{
					{Type: "long", Name: "__syscall_nr"},
					{Type: "int", Name: "error_code"},
				},
			})
			if r.Kind != KindNull {
				t.Errorf("%s: got kind %d, want KindNull", name, r.Kind)
			}
		})
	}
}

// --- End-to-end classification with enter+exit pairs ---

func TestClassifySyscallPairAccepted(t *testing.T) {
	tests := []struct {
		name      string
		enter     string
		exit      string
		enterKind TracepointKind
	}{
		{"read", FormatRead, FormatExitRead, KindFd},
		{"lseek", FormatLseek, FormatExitLseek, KindFd},
		{"openat", FormatOpenat, FormatExitOpenat, KindOpen},
		{"rename", FormatRename, FormatExitRename, KindName},
		{"close", FormatClose, FormatExitClose, KindFd},
		{"dup3", FormatDup3, FormatExitDup3, KindDup3},
		{"fcntl", FormatFcntl, FormatExitFcntl, KindFcntl},
		{"sync", FormatSync, FormatExitSync, KindNull},
		{"msync", FormatMsync, FormatExitMsync, KindNull},
		{"getcwd", FormatGetcwd, FormatExitGetcwd, KindNull},
		{"pidfd_getfd", FormatPidfdGetfd, FormatExitPidfdGetfd, KindFd},
		{"copy_file_range", FormatCopyFileRange, FormatExitCopyFileRange, KindFd},
		{"syslog", FormatSyslog, FormatExitSyslog, KindNull},
		{"open_by_handle_at", FormatOpenByHandleAt, FormatExitOpenByHandleAt, KindOpenByHandleAt},
		{"name_to_handle_at", FormatNameToHandleAt, FormatExitNameToHandleAt, KindPathname},
		{"io_uring_enter", FormatIoUringEnter, FormatExitIoUringEnter, KindFd},
		{"io_uring_register", FormatIoUringRegister, FormatExitIoUringRegister, KindFd},
		{"pread64", FormatPread64, FormatExitPread64, KindFd},
		{"symlink", FormatSymlink, FormatExitSymlink, KindName},
		{"mknod", FormatMknod, FormatExitMknod, KindPathname},
		{"mknodat", FormatMknodat, FormatExitMknodat, KindPathname},
		{"execve", FormatExecve, FormatExitExecve, KindExec},
		{"execveat", FormatExecveat, FormatExitExecveat, KindExec},
		{"accept", FormatAccept, FormatExitAccept, KindAccept},
		{"accept4", FormatAccept4, FormatExitAccept4, KindAccept},
		{"socket", FormatSocket, FormatExitSocket, KindSocket},
		{"socketpair", FormatSocketpair, FormatExitSocketpair, KindSocketpair},
		{"pipe", FormatPipe, FormatExitPipe, KindPipe},
		{"pipe2", FormatPipe2, FormatExitPipe2, KindPipe},
		{"eventfd", FormatEventfd, FormatExitEventfd, KindEventfd},
		{"eventfd2", FormatEventfd2, FormatExitEventfd2, KindEventfd},
		{"epoll_create", syntheticEnter("epoll_create", 9340), syntheticExit("epoll_create", 9339), KindEventfd},
		{"epoll_create1", syntheticEnter("epoll_create1", 9342), syntheticExit("epoll_create1", 9341), KindEventfd},
		{"inotify_init", syntheticEnter("inotify_init", 9344), syntheticExit("inotify_init", 9343), KindEventfd},
		{"inotify_init1", syntheticEnter("inotify_init1", 9346), syntheticExit("inotify_init1", 9345), KindEventfd},
		{"fanotify_init", syntheticEnter("fanotify_init", 9348), syntheticExit("fanotify_init", 9347), KindEventfd},
		{"landlock_create_ruleset", syntheticEnter("landlock_create_ruleset", 9350), syntheticExit("landlock_create_ruleset", 9349), KindEventfd},
		{"landlock_add_rule", syntheticEnter("landlock_add_rule", 9418), syntheticExit("landlock_add_rule", 9417), KindFd},
		{"landlock_restrict_self", syntheticEnter("landlock_restrict_self", 9420), syntheticExit("landlock_restrict_self", 9419), KindFd},
		{"fsopen", syntheticEnter("fsopen", 9352), syntheticExit("fsopen", 9351), KindEventfd},
		{"pidfd_open", syntheticEnter("pidfd_open", 9320), syntheticExit("pidfd_open", 9319), KindPidfd},
		{"pidfd_send_signal", syntheticEnter("pidfd_send_signal", 9322), syntheticExit("pidfd_send_signal", 9321), KindFd},
		{"epoll_ctl", FormatEpollCtl, FormatExitEpollCtl, KindEpollCtl},
		{"epoll_wait", FormatEpollWait, FormatExitEpollWait, KindFd},
		{"epoll_pwait", FormatEpollPwait, FormatExitEpollPwait, KindFd},
		{"epoll_pwait2", FormatEpollPwait2, FormatExitEpollPwait2, KindFd},
		{"poll", FormatPoll, FormatExitPoll, KindPoll},
		{"ppoll", FormatPpoll, FormatExitPpoll, KindPoll},
		{"select", FormatSelect, FormatExitSelect, KindPoll},
		{"pselect6", FormatPselect6, FormatExitPselect6, KindPoll},
		{"munmap", FormatMunmap, FormatExitMunmap, KindMem},
		{"mremap", FormatMremap, FormatExitMremap, KindMem},
		{"mincore", syntheticEnter("mincore", 9354), syntheticExit("mincore", 9353), KindMem},
		{"remap_file_pages", syntheticEnter("remap_file_pages", 9356), syntheticExit("remap_file_pages", 9355), KindMem},
		{"mlock", syntheticEnter("mlock", 9358), syntheticExit("mlock", 9357), KindMem},
		{"mlock2", syntheticEnter("mlock2", 9360), syntheticExit("mlock2", 9359), KindMem},
		{"munlock", syntheticEnter("munlock", 9362), syntheticExit("munlock", 9361), KindMem},
		{"mseal", syntheticEnter("mseal", 9364), syntheticExit("mseal", 9363), KindMem},
		{"map_shadow_stack", syntheticEnter("map_shadow_stack", 9366), syntheticExit("map_shadow_stack", 9365), KindMem},
		{"nanosleep", FormatNanosleep, FormatExitNanosleep, KindSleep},
		{"clock_nanosleep", FormatClockNanosleep, FormatExitClockNanosleep, KindSleep},
		{"keyctl", syntheticEnter("keyctl", 9200), syntheticExit("keyctl", 9199), KindKeyctl},
		{"add_key", syntheticEnter("add_key", 9202), syntheticExit("add_key", 9201), KindKeyctl},
		{"request_key", syntheticEnter("request_key", 9204), syntheticExit("request_key", 9203), KindKeyctl},
		{"ptrace", syntheticEnter("ptrace", 9206), syntheticExit("ptrace", 9205), KindPtrace},
		{"perf_event_open", syntheticEnter("perf_event_open", 9208), syntheticExit("perf_event_open", 9207), KindPerfOpen},
		{"seccomp", syntheticEnter("seccomp", 9368), syntheticExit("seccomp", 9367), KindSeccomp},
		{"init_module", syntheticEnter("init_module", 9370), syntheticExit("init_module", 9369), KindModule},
		{"delete_module", syntheticEnter("delete_module", 9372), syntheticExit("delete_module", 9371), KindModule},
		{"msgget", syntheticEnter("msgget", 9394), syntheticExit("msgget", 9393), KindSysVId},
		{"semget", syntheticEnter("semget", 9396), syntheticExit("semget", 9395), KindSysVId},
		{"shmget", syntheticEnter("shmget", 9398), syntheticExit("shmget", 9397), KindSysVId},
		{"msgsnd", syntheticEnter("msgsnd", 9400), syntheticExit("msgsnd", 9399), KindSysVOp},
		{"msgrcv", syntheticEnter("msgrcv", 9402), syntheticExit("msgrcv", 9401), KindSysVOp},
		{"msgctl", syntheticEnter("msgctl", 9404), syntheticExit("msgctl", 9403), KindSysVOp},
		{"semop", syntheticEnter("semop", 9406), syntheticExit("semop", 9405), KindSysVOp},
		{"semtimedop", syntheticEnter("semtimedop", 9408), syntheticExit("semtimedop", 9407), KindSysVOp},
		{"semctl", syntheticEnter("semctl", 9410), syntheticExit("semctl", 9409), KindSysVOp},
		{"shmat", syntheticEnter("shmat", 9412), syntheticExit("shmat", 9411), KindSysVOp},
		{"shmdt", syntheticEnter("shmdt", 9414), syntheticExit("shmdt", 9413), KindSysVOp},
		{"shmctl", syntheticEnter("shmctl", 9416), syntheticExit("shmctl", 9415), KindSysVOp},
		{"mount", FormatMount, FormatExitMount, KindPathname},
		{"umount", FormatUmount, FormatExitUmount, KindPathname},
		{"move_mount", FormatMoveMount, FormatExitMoveMount, KindTwoFd},
		{"close_range", syntheticEnter("close_range", 9322), syntheticExit("close_range", 9321), KindTwoFd},
		{"kcmp", syntheticEnter("kcmp", 9324), syntheticExit("kcmp", 9323), KindTwoFd},
		{"kexec_file_load", syntheticEnter("kexec_file_load", 9326), syntheticExit("kexec_file_load", 9325), KindFd},
		{"membarrier", syntheticEnter("membarrier", 9328), syntheticExit("membarrier", 9327), KindNull},
		{"rseq", syntheticEnter("rseq", 9330), syntheticExit("rseq", 9329), KindNull},
		{"set_robust_list", syntheticEnter("set_robust_list", 9332), syntheticExit("set_robust_list", 9331), KindNull},
		{"get_robust_list", syntheticEnter("get_robust_list", 9334), syntheticExit("get_robust_list", 9333), KindNull},
		{"mmap2", syntheticEnter("mmap2", 9336), syntheticExit("mmap2", 9335), KindNull},
		{"kexec_load", syntheticEnter("kexec_load", 9338), syntheticExit("kexec_load", 9337), KindNull},
		{"fsmount", FormatFsmount, FormatExitFsmount, KindEventfd},
		{"pivot_root", FormatPivotRoot, FormatExitPivotRoot, KindPathname},
		{"quotactl", FormatQuotactl, FormatExitQuotactl, KindPathname},
		{"statmount", FormatStatmount, FormatExitStatmount, KindNull},
		{"listmount", FormatListmount, FormatExitListmount, KindNull},
		{"listns", FormatListns, FormatExitListns, KindNull},
		{"swapon", FormatSwapon, FormatExitSwapon, KindPathname},
		{"swapoff", FormatSwapoff, FormatExitSwapoff, KindPathname},
		{"kill", FormatKill, FormatExitKill, KindNull},
		{"rt_sigaction", syntheticEnter("rt_sigaction", 9374), syntheticExit("rt_sigaction", 9373), KindNull},
		{"rt_sigprocmask", syntheticEnter("rt_sigprocmask", 9376), syntheticExit("rt_sigprocmask", 9375), KindNull},
		{"rt_sigpending", syntheticEnter("rt_sigpending", 9378), syntheticExit("rt_sigpending", 9377), KindNull},
		{"rt_sigsuspend", syntheticEnter("rt_sigsuspend", 9380), syntheticExit("rt_sigsuspend", 9379), KindNull},
		{"rt_sigtimedwait", syntheticEnter("rt_sigtimedwait", 9382), syntheticExit("rt_sigtimedwait", 9381), KindNull},
		{"rt_sigreturn", syntheticEnter("rt_sigreturn", 9384), syntheticExit("rt_sigreturn", 9383), KindNull},
		{"sigaltstack", syntheticEnter("sigaltstack", 9386), syntheticExit("sigaltstack", 9385), KindNull},
		{"pause", syntheticEnter("pause", 9388), syntheticExit("pause", 9387), KindNull},
		{"rt_sigqueueinfo", syntheticEnter("rt_sigqueueinfo", 9390), syntheticExit("rt_sigqueueinfo", 9389), KindNull},
		{"rt_tgsigqueueinfo", syntheticEnter("rt_tgsigqueueinfo", 9392), syntheticExit("rt_tgsigqueueinfo", 9391), KindNull},
		{"exit", syntheticEnter("exit", 9310), syntheticExit("exit", 9309), KindNull},
		{"exit_group", syntheticEnter("exit_group", 9312), syntheticExit("exit_group", 9311), KindNull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.enter + "\n" + tt.exit
			output := GenerateTracepointsC(mustParseAll(t, input))
			if strings.Contains(output, "Ignoring") {
				t.Errorf("syscall %s was ignored, expected accepted", tt.name)
			}
		})
	}
}

func TestClassifySyscallPairEmitsAllFamilies(t *testing.T) {
	tests := []struct {
		name   string
		enter  string
		exit   string
		family SyscallFamily
	}{
		{"mknod", FormatMknod, FormatExitMknod, FamilyFS},
		{"mknodat", FormatMknodat, FormatExitMknodat, FamilyFS},
		{"execve", FormatExecve, FormatExitExecve, FamilyProcess},
		{"execveat", FormatExecveat, FormatExitExecveat, FamilyProcess},
		{"accept", FormatAccept, FormatExitAccept, FamilyNetwork},
		{"accept4", FormatAccept4, FormatExitAccept4, FamilyNetwork},
		{"socket", FormatSocket, FormatExitSocket, FamilyNetwork},
		{"socketpair", FormatSocketpair, FormatExitSocketpair, FamilyNetwork},
		{"pipe", FormatPipe, FormatExitPipe, FamilyIPC},
		{"pipe2", FormatPipe2, FormatExitPipe2, FamilyIPC},
		{"eventfd", FormatEventfd, FormatExitEventfd, FamilyIPC},
		{"eventfd2", FormatEventfd2, FormatExitEventfd2, FamilyIPC},
		{"epoll_ctl", FormatEpollCtl, FormatExitEpollCtl, FamilyPolling},
		{"epoll_wait", FormatEpollWait, FormatExitEpollWait, FamilyPolling},
		{"poll", FormatPoll, FormatExitPoll, FamilyPolling},
		{"ppoll", FormatPpoll, FormatExitPpoll, FamilyPolling},
		{"select", FormatSelect, FormatExitSelect, FamilyPolling},
		{"pselect6", FormatPselect6, FormatExitPselect6, FamilyPolling},
		{"munmap", FormatMunmap, FormatExitMunmap, FamilyMemory},
		{"mremap", FormatMremap, FormatExitMremap, FamilyMemory},
		{"nanosleep", FormatNanosleep, FormatExitNanosleep, FamilyTime},
		{"clock_nanosleep", FormatClockNanosleep, FormatExitClockNanosleep, FamilyTime},
		{"keyctl", syntheticEnter("keyctl", 9300), syntheticExit("keyctl", 9299), FamilySecurity},
		{"add_key", syntheticEnter("add_key", 9302), syntheticExit("add_key", 9301), FamilySecurity},
		{"request_key", syntheticEnter("request_key", 9304), syntheticExit("request_key", 9303), FamilySecurity},
		{"ptrace", syntheticEnter("ptrace", 9306), syntheticExit("ptrace", 9305), FamilySecurity},
		{"perf_event_open", syntheticEnter("perf_event_open", 9308), syntheticExit("perf_event_open", 9307), FamilySecurity},
		// lsm_* are the Linux Security Module introspection syscalls (Linux
		// 6.8+); they belong with their landlock_*/keyctl/*_key siblings in
		// the Security family, not Misc.
		{"lsm_list_modules", syntheticEnter("lsm_list_modules", 9412), syntheticExit("lsm_list_modules", 9411), FamilySecurity},
		{"lsm_get_self_attr", syntheticEnter("lsm_get_self_attr", 9414), syntheticExit("lsm_get_self_attr", 9413), FamilySecurity},
		{"lsm_set_self_attr", syntheticEnter("lsm_set_self_attr", 9416), syntheticExit("lsm_set_self_attr", 9415), FamilySecurity},
		{"mount", FormatMount, FormatExitMount, FamilyFS},
		{"umount", FormatUmount, FormatExitUmount, FamilyFS},
		{"move_mount", FormatMoveMount, FormatExitMoveMount, FamilyFS},
		{"fsmount", FormatFsmount, FormatExitFsmount, FamilyFS},
		{"quotactl", FormatQuotactl, FormatExitQuotactl, FamilyFS},
		{"statmount", FormatStatmount, FormatExitStatmount, FamilyFS},
		{"listmount", FormatListmount, FormatExitListmount, FamilyFS},
		{"listns", FormatListns, FormatExitListns, FamilyFS},
		{"swapon", FormatSwapon, FormatExitSwapon, FamilyFS},
		{"swapoff", FormatSwapoff, FormatExitSwapoff, FamilyFS},
		// Bare sync() takes no args and returns void, but it DOES return (it is
		// not noreturn like exit/exit_group), so it belongs in FamilyFS and must
		// still emit a live exit handler. Its fd-taking siblings (syncfs/fsync/
		// fdatasync/sync_file_range) are FamilyFS+KindFd and covered elsewhere.
		{"sync", FormatSync, FormatExitSync, FamilyFS},
		{"kill", FormatKill, FormatExitKill, FamilySignals},
		{"exit_group", syntheticEnter("exit_group", 9316), syntheticExit("exit_group", 9315), FamilyProcess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.enter + "\n" + tt.exit
			formats := mustParseAll(t, input)
			if formats[0].Family != tt.family {
				t.Fatalf("%s family = %s, want %s", tt.name, formats[0].Family, tt.family)
			}
			output := GenerateTracepointsC(formats)
			if strings.Contains(output, "Ignoring") {
				t.Errorf("syscall %s was ignored, expected accepted", tt.name)
			}
			if !strings.Contains(output, `SEC("tracepoint/syscalls/sys_enter_`+tt.name+`")`) {
				t.Errorf("syscall %s missing enter handler", tt.name)
			}
			// Noreturn syscalls (exit, exit_group) are deliberately exempt from
			// the exit-handler requirement: their sys_exit handler can never
			// fire because the syscall never returns, so codegen suppresses it
			// via isNoreturnSyscall (see TestGenerateExitNoreturnHandlers). For
			// every other syscall the exit handler is still required.
			hasExitHandler := strings.Contains(output, `SEC("tracepoint/syscalls/sys_exit_`+tt.name+`")`)
			if isNoreturnSyscall(tt.name) {
				if hasExitHandler {
					t.Errorf("noreturn syscall %s must not emit an exit handler", tt.name)
				}
			} else if !hasExitHandler {
				t.Errorf("syscall %s missing exit handler", tt.name)
			}
		})
	}
}

func TestClassifyPhaseAByteSyscallPairsAccepted(t *testing.T) {
	tests := []struct {
		name          string
		enterKindText string
		retText       string
	}{
		{"recvfrom", "struct fd_event", "READ_CLASSIFIED"},
		{"recvmsg", "struct fd_event", "READ_CLASSIFIED"},
		{"sendto", "struct fd_event", "WRITE_CLASSIFIED"},
		{"sendmsg", "struct fd_event", "WRITE_CLASSIFIED"},
		{"sendfile64", "struct fd_event", "TRANSFER_CLASSIFIED"},
		{"splice", "struct null_event", "TRANSFER_CLASSIFIED"},
		{"tee", "struct null_event", "TRANSFER_CLASSIFIED"},
		{"process_vm_readv", "struct null_event", "READ_CLASSIFIED"},
		{"process_vm_writev", "struct null_event", "WRITE_CLASSIFIED"},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formats := phaseAFormats(tt.name, 9000+i*2)
			output := GenerateTracepointsC(formats)
			if strings.Contains(output, "Ignoring") || strings.Contains(output, "Skipping") {
				t.Fatalf("syscall %s was not accepted:\n%s", tt.name, output)
			}
			if !strings.Contains(output, "/// sys_enter_"+tt.name+" is a "+tt.enterKindText) {
				t.Fatalf("sys_enter_%s did not use %s:\n%s", tt.name, tt.enterKindText, output)
			}
			if !strings.Contains(output, "/// sys_exit_"+tt.name+" is a struct ret_event ("+tt.retText+")") {
				t.Fatalf("sys_exit_%s did not use %s:\n%s", tt.name, tt.retText, output)
			}
		})
	}
}

func TestBatchMessageSyscallPairsDeferByteClassification(t *testing.T) {
	tests := []string{"sendmmsg", "recvmmsg"}
	for i, name := range tests {
		t.Run(name, func(t *testing.T) {
			output := GenerateTracepointsC(phaseAFormats(name, 9100+i*2))
			if strings.Contains(output, "Ignoring") || strings.Contains(output, "Skipping") {
				t.Fatalf("syscall %s was not accepted:\n%s", name, output)
			}
			if !strings.Contains(output, "/// sys_exit_"+name+" is a struct ret_event (UNCLASSIFIED)") {
				t.Fatalf("sys_exit_%s should be generated without byte classification:\n%s", name, output)
			}
		})
	}
}

func TestClassifyMqSyscallPairsAcceptedAndClassified(t *testing.T) {
	tests := []struct {
		name               string
		enterKindText      string
		exitClassification string
	}{
		{"mq_open", "struct open_event", "UNCLASSIFIED"},
		{"mq_unlink", "struct path_event", "UNCLASSIFIED"},
		{"mq_timedsend", "struct fd_event", "WRITE_CLASSIFIED"},
		{"mq_timedreceive", "struct fd_event", "READ_CLASSIFIED"},
		{"mq_notify", "struct fd_event", "UNCLASSIFIED"},
		{"mq_getsetattr", "struct fd_event", "UNCLASSIFIED"},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := GenerateTracepointsC(mqFormats(tt.name, 9200+i*2))
			if strings.Contains(output, "Ignoring") || strings.Contains(output, "Skipping") {
				t.Fatalf("syscall %s was not accepted:\n%s", tt.name, output)
			}
			if !strings.Contains(output, "/// sys_enter_"+tt.name+" is a "+tt.enterKindText) {
				t.Fatalf("sys_enter_%s did not use %s:\n%s", tt.name, tt.enterKindText, output)
			}
			if !strings.Contains(output, "/// sys_exit_"+tt.name+" is a struct ret_event ("+tt.exitClassification+")") {
				t.Fatalf("sys_exit_%s did not use %s:\n%s", tt.name, tt.exitClassification, output)
			}
		})
	}
}

func phaseAFormats(name string, enterID int) []Format {
	enterFields := []Field{
		{Type: "long", Name: "__syscall_nr"},
	}
	if name == "sendto" || name == "recvfrom" || name == "sendmsg" || name == "recvmsg" ||
		name == "sendmmsg" || name == "recvmmsg" {
		enterFields = append(enterFields, Field{Type: "int", Name: "fd"})
	}

	return []Format{
		{
			Name:           "sys_enter_" + name,
			ID:             enterID,
			Family:         ClassifySyscallFamily("sys_enter_" + name),
			ExternalFields: enterFields,
		},
		{
			Name:   "sys_exit_" + name,
			ID:     enterID - 1,
			Family: ClassifySyscallFamily("sys_exit_" + name),
			ExternalFields: []Field{
				{Type: "long", Name: "__syscall_nr"},
				{Type: "long", Name: "ret"},
			},
		},
	}
}

func mqFormats(name string, enterID int) []Format {
	enterFields := []Field{
		{Type: "long", Name: "__syscall_nr"},
	}
	switch name {
	case "mq_open":
		enterFields = append(enterFields,
			Field{Type: "const char *", Name: "u_name"},
			Field{Type: "int", Name: "oflag"},
			Field{Type: "umode_t", Name: "mode"},
		)
	case "mq_unlink":
		enterFields = append(enterFields, Field{Type: "const char *", Name: "u_name"})
	default:
		enterFields = append(enterFields, Field{Type: "mqd_t", Name: "mqdes"})
	}

	return []Format{
		{
			Name:           "sys_enter_" + name,
			ID:             enterID,
			Family:         ClassifySyscallFamily("sys_enter_" + name),
			ExternalFields: enterFields,
		},
		{
			Name:   "sys_exit_" + name,
			ID:     enterID - 1,
			Family: ClassifySyscallFamily("sys_exit_" + name),
			ExternalFields: []Field{
				{Type: "long", Name: "__syscall_nr"},
				{Type: "long", Name: "ret"},
			},
		},
	}
}

func syntheticEnter(syscall string, id int) string {
	return strings.Replace(strings.Replace(FormatKill, "sys_enter_kill", "sys_enter_"+syscall, 1), "ID: 183", "ID: "+itoa(id), 1)
}

func syntheticExit(syscall string, id int) string {
	return strings.Replace(strings.Replace(FormatExitKill, "sys_exit_kill", "sys_exit_"+syscall, 1), "ID: 182", "ID: "+itoa(id), 1)
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

func TestClassifyFormatNoExternalFields(t *testing.T) {
	f := &Format{
		Name:           "sys_enter_test",
		ID:             999,
		ExternalFields: nil,
	}
	r := ClassifyFormat(f)
	if r.Kind != KindNone {
		t.Errorf("ClassifyFormat with empty ExternalFields: got kind %d, want KindNone", r.Kind)
	}
}

func TestClassifyNameOnlyTables(t *testing.T) {
	tests := []struct {
		name string
		want TracepointKind
	}{
		{"sys_enter_open_by_handle_at", KindOpenByHandleAt},
		{"sys_exit_socketpair", KindSocketpair},
		{"sys_enter_pidfd_open", KindPidfd},
		{"sys_enter_epoll_ctl", KindEpollCtl},
		{"sys_enter_perf_event_open", KindPerfOpen},
		{"sys_enter_futex", KindFutex},
		{"sys_enter_clone", KindProc},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := classifyNameOnly(tt.name)
			if !ok {
				t.Fatalf("classifyNameOnly(%q) did not match", tt.name)
			}
			if r.Kind != tt.want {
				t.Fatalf("classifyNameOnly(%q) kind = %d, want %d", tt.name, r.Kind, tt.want)
			}
		})
	}
}

func TestClassifyNameOnlyPrefixKinds(t *testing.T) {
	r, ok := classifyNameOnly("sys_enter_io_destroy")
	if !ok {
		t.Fatal("classifyNameOnly(sys_enter_io_destroy) did not match prefix metadata")
	}
	if r.Kind != KindNull {
		t.Fatalf("classifyNameOnly(sys_enter_io_destroy) kind = %d, want KindNull", r.Kind)
	}

	r, ok = classifyNameOnly("sys_enter_io_uring_enter")
	if !ok {
		t.Fatal("classifyNameOnly(sys_enter_io_uring_enter) did not match exact metadata")
	}
	if r.Kind != KindFd {
		t.Fatalf("classifyNameOnly(sys_enter_io_uring_enter) kind = %d, want KindFd", r.Kind)
	}
}

// TestIoUringRegisterTablePrecedenceOverIoPrefix is an audit lock-in for
// io_uring_register(2): int io_uring_register(unsigned int fd, unsigned int
// opcode, void *arg, unsigned int nr_args). The io_uring fd lives at args[0],
// so the syscall MUST classify as KindFd (a single-fd fd_event) rather than
// falling through to the generic `sys_enter_io_` KindNull prefix rule shared
// with io_setup/io_destroy/io_submit/io_getevents. classifyNameOnly consults
// the exact nameOnlyKindsTable BEFORE the nameOnlyPrefixKinds list, so the
// explicit KindFd entry wins. This test would fail if that entry were removed
// (leaving the prefix rule to wrongly produce KindNull and drop the fd) or if
// table-vs-prefix lookup order were reversed.
func TestIoUringRegisterTablePrecedenceOverIoPrefix(t *testing.T) {
	r, ok := classifyNameOnly("sys_enter_io_uring_register")
	if !ok {
		t.Fatal("classifyNameOnly(sys_enter_io_uring_register) did not match")
	}
	if r.Kind != KindFd {
		t.Fatalf("io_uring_register kind = %d, want KindFd (fd at args[0]); the "+
			"sys_enter_io_ KindNull prefix rule must not win", r.Kind)
	}

	// Sanity check the prefix rule itself still maps the io_* AIO siblings that
	// have no fd argument to KindNull, so the precedence above is meaningful.
	if pr, ok := classifyNameOnly("sys_enter_io_submit"); !ok || pr.Kind != KindNull {
		t.Fatalf("sys_enter_io_submit kind = %d (ok=%v), want KindNull via prefix rule", pr.Kind, ok)
	}
}

// TestIoUringRegisterReturnUnclassified locks in that io_uring_register's exit
// is UNCLASSIFIED: on success it returns 0 or a small positive value (e.g. an
// fd or count specific to the opcode), never a byte-transfer count, so it must
// not appear in retClassifications as READ/WRITE/TRANSFER. Treating it as a
// byte count would corrupt throughput accounting. Its io_uring siblings
// (io_uring_setup/io_uring_enter) are likewise unclassified.
func TestIoUringRegisterReturnUnclassified(t *testing.T) {
	for _, name := range []string{
		"sys_exit_io_uring_register",
		"sys_exit_io_uring_enter",
		"sys_exit_io_uring_setup",
	} {
		if got := ClassifyRet(name); got != Unclassified {
			t.Errorf("ClassifyRet(%q) = %q, want %q", name, got, Unclassified)
		}
	}
}

func TestClassifyNameOnlyUnknown(t *testing.T) {
	if r, ok := classifyNameOnly("sys_enter_not_real"); ok {
		t.Fatalf("classifyNameOnly matched unknown syscall with kind %d", r.Kind)
	}
}

func TestNameOnlyKindMetadataIsValid(t *testing.T) {
	for name, kind := range nameOnlyKindsTable {
		if name == "" {
			t.Fatal("nameOnlyKindsTable contains an empty syscall name")
		}
		if kind == KindNone {
			t.Fatalf("nameOnlyKindsTable[%q] = KindNone", name)
		}
	}

	for _, prefixKind := range nameOnlyPrefixKinds {
		if prefixKind.prefix == "" {
			t.Fatal("nameOnlyPrefixKinds contains an empty prefix")
		}
		if prefixKind.kind == KindNone {
			t.Fatalf("nameOnlyPrefixKinds[%q] = KindNone", prefixKind.prefix)
		}
	}
}

func TestIsFdTypeNonMatch(t *testing.T) {
	nonFdTypes := []string{
		"const char *",
		"long",
		"size_t",
		"pid_t",
		"umode_t",
		"char *",
		"void *",
	}
	for _, typ := range nonFdTypes {
		if isFdType(typ) {
			t.Errorf("isFdType(%q) = true, want false", typ)
		}
	}
}

// TestClassifySchedGetattrPidNotFd is a lock-in regression test for the
// sched_getattr audit. The syscall signature is:
//
//	int sched_getattr(pid_t pid, struct sched_attr *attr,
//	                  unsigned int size, unsigned int flags)
//
// args[0] is a PID (a process/thread id), NOT a file descriptor, and attr is
// a userspace output pointer. The expected classification is KindNull (no fd,
// pathname, or other resource handle is extracted on enter) and family Sched.
//
// The critical invariant guarded here is that the pid argument must never be
// misclassified as an fd. ClassifyFormat resolves sched_getattr via the
// name-only table first, which short-circuits before any field heuristic;
// this test pins that behavior even when the real kernel field layout (whose
// first arg is named "pid", not "fd") is supplied.
func TestClassifySchedGetattrPidNotFd(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_sched_getattr: pid_t pid, struct sched_attr *uattr,
	// unsigned int usize, unsigned int flags.
	r := ClassifyFormat(&Format{
		Name: "sys_enter_sched_getattr",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_attr *", Name: "uattr"},
			{Type: "unsigned int", Name: "usize"},
			{Type: "unsigned int", Name: "flags"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("sched_getattr: got kind %d, want KindNull (pid arg must not be treated as fd)", r.Kind)
	}
	if r.Kind == KindFd {
		t.Fatalf("sched_getattr: pid arg misclassified as fd")
	}

	// Family must match the Sched siblings (sched_setattr, sched_getparam,
	// sched_getscheduler, ...).
	if fam := ClassifySyscallFamily("sys_enter_sched_getattr"); fam != FamilySched {
		t.Fatalf("sched_getattr: got family %s, want FamilySched", fam)
	}

	// Sanity-check sibling consistency: the matching setter and the other
	// getters share the same family and KindNull classification.
	siblings := []string{
		"sys_enter_sched_setattr",
		"sys_enter_sched_getparam",
		"sys_enter_sched_getscheduler",
	}
	for _, name := range siblings {
		s := ClassifyFormat(&Format{
			Name: name,
			ExternalFields: []Field{
				{Type: "long", Name: "__syscall_nr"},
				{Type: "long", Name: "arg0"},
			},
		})
		if s.Kind != KindNull {
			t.Errorf("%s: got kind %d, want KindNull", name, s.Kind)
		}
		if fam := ClassifySyscallFamily(name); fam != FamilySched {
			t.Errorf("%s: got family %s, want FamilySched", name, fam)
		}
	}
}

// TestClassifySchedGetparamPidNotFd is a lock-in regression test for the
// sched_getparam(2) audit. The syscall signature is:
//
//	int sched_getparam(pid_t pid, struct sched_param *param)
//
// args[0] is a PID (a thread/process id; 0 means the calling thread), NOT a
// file descriptor, and param is a userspace output pointer to a struct
// sched_param. No fd or filesystem path is involved, so the enter tracepoint
// must classify as KindNull (plain null_event; the pid must never be picked up
// as an fd). On success sched_getparam returns 0 (-1 on error) and transfers no
// byte count, so its exit stays KindRet / UNCLASSIFIED — exactly like its
// sibling sched_getattr and the setter sched_setparam.
func TestClassifySchedGetparamPidNotFd(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_sched_getparam: pid_t pid, struct sched_param *param.
	r := ClassifyFormat(&Format{
		Name: "sys_enter_sched_getparam",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param *", Name: "param"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("sched_getparam: got kind %d, want KindNull (pid arg must not be treated as fd)", r.Kind)
	}
	if r.Kind == KindFd {
		t.Fatalf("sched_getparam: pid arg misclassified as fd")
	}

	// Family must match the Sched siblings (sched_setparam, sched_getattr, ...).
	if fam := ClassifySyscallFamily("sys_enter_sched_getparam"); fam != FamilySched {
		t.Fatalf("sched_getparam: got family %s, want FamilySched", fam)
	}

	// Exit returns int 0/-1 (a status code, not a transferred byte count), so
	// the return must classify as KindRet / UNCLASSIFIED.
	exit := ClassifyFormat(&Format{
		Name: "sys_exit_sched_getparam",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if exit.Kind != KindRet {
		t.Fatalf("exit_sched_getparam: got kind %d, want KindRet", exit.Kind)
	}
	if got := ClassifyRet("sys_exit_sched_getparam"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_sched_getparam) = %q, want UNCLASSIFIED", got)
	}

	// Sibling consistency: the matching setter shares family Sched and KindNull.
	if s := ClassifyFormat(&Format{
		Name: "sys_enter_sched_setparam",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param *", Name: "param"},
		},
	}); s.Kind != KindNull {
		t.Errorf("sched_setparam: got kind %d, want KindNull", s.Kind)
	}
	if fam := ClassifySyscallFamily("sys_enter_sched_setparam"); fam != FamilySched {
		t.Errorf("sched_setparam: got family %s, want FamilySched", fam)
	}
}

// TestClassifySchedSetparamPidNotFd is a lock-in regression test for the
// sched_setparam(2) audit. The syscall signature is:
//
//	int sched_setparam(pid_t pid, const struct sched_param *param)
//
// args[0] is a PID (the thread/process whose scheduling parameters are set; 0
// means the calling thread), NOT a file descriptor, and param is a userspace
// input pointer to a struct sched_param. No fd or filesystem path is involved,
// so the enter tracepoint must classify as KindNull (plain null_event; the pid
// must never be picked up as an fd). On success sched_setparam returns 0 (-1 on
// error) and transfers no byte count, so its exit stays KindRet / UNCLASSIFIED
// — exactly like its getter sibling sched_getparam and sched_setscheduler.
func TestClassifySchedSetparamPidNotFd(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_sched_setparam: pid_t pid, const struct sched_param *param.
	r := ClassifyFormat(&Format{
		Name: "sys_enter_sched_setparam",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "const struct sched_param *", Name: "param"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("sched_setparam: got kind %d, want KindNull (pid arg must not be treated as fd)", r.Kind)
	}
	if r.Kind == KindFd {
		t.Fatalf("sched_setparam: pid arg misclassified as fd")
	}

	// Family must match the Sched siblings (sched_getparam, sched_setscheduler, ...).
	if fam := ClassifySyscallFamily("sys_enter_sched_setparam"); fam != FamilySched {
		t.Fatalf("sched_setparam: got family %s, want FamilySched", fam)
	}

	// Exit returns int 0/-1 (a status code, not a transferred byte count), so
	// the return must classify as KindRet / UNCLASSIFIED.
	exit := ClassifyFormat(&Format{
		Name: "sys_exit_sched_setparam",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "long", Name: "ret"},
		},
	})
	if exit.Kind != KindRet {
		t.Fatalf("exit_sched_setparam: got kind %d, want KindRet", exit.Kind)
	}
	if got := ClassifyRet("sys_exit_sched_setparam"); got != Unclassified {
		t.Errorf("ClassifyRet(sys_exit_sched_setparam) = %q, want UNCLASSIFIED", got)
	}

	// Sibling consistency: the matching getter shares family Sched and KindNull.
	if g := ClassifyFormat(&Format{
		Name: "sys_enter_sched_getparam",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "pid_t", Name: "pid"},
			{Type: "struct sched_param *", Name: "param"},
		},
	}); g.Kind != KindNull {
		t.Errorf("sched_getparam: got kind %d, want KindNull", g.Kind)
	}
	if fam := ClassifySyscallFamily("sys_enter_sched_getparam"); fam != FamilySched {
		t.Errorf("sched_getparam: got family %s, want FamilySched", fam)
	}
}

// TestClassifyGetRobustListPidNotFd is a lock-in regression test for the
// get_robust_list(2) / set_robust_list(2) audit. The signatures are:
//
//	long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr)
//	long set_robust_list(struct robust_list_head *head, size_t len)
//
// get_robust_list's args[0] is a PID (a thread/process identifier), NOT a file
// descriptor, and head_ptr/len_ptr are userspace output pointers; set_robust_list
// takes a userspace head pointer and a length. Neither syscall touches an fd or a
// filesystem path, so both enter as KindNull (plain null_event). On success both
// return 0 (-1 on error) and transfer no byte count, so their exits stay
// UNCLASSIFIED.
//
// Invariants pinned here:
//   - enter classifies as KindNull (the pid arg must NOT be picked up as an fd),
//   - family is Misc — grouped with the per-thread sibling rseq, not promoted to
//     IPC like the futex_* shared-memory primitives (see family.go / family_test.go),
//   - return classifies as UNCLASSIFIED (0/-1, no byte transfer).
//
// FAMILY DECISION (resolved): get_robust_list/set_robust_list stay FamilyMisc and
// are NOT moved to FamilyIPC for "futex consistency". The boundary rule (spelled
// out next to the futex block in family.go) is operation-vs-registration: a
// syscall is IPC only if it PERFORMS the actual IPC/sync operation (futex
// wait/wake/requeue, or an op on an IPC object). These two only register/query
// the per-thread robust-futex list head pointer — per get_robust_list(2) the list
// is "managed in user space: the kernel knows only about the location of the head"
// — and never wait, wake, or touch the shared futex word. That is per-thread
// bookkeeping, structurally identical to rseq, so they share rseq's Misc family.
// The contrast assertion below (futex == IPC) pins both sides of the boundary.
func TestClassifyGetRobustListPidNotFd(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_get_robust_list: int pid, struct robust_list_head **head_ptr,
	// size_t *len_ptr.
	r := ClassifyFormat(&Format{
		Name: "sys_enter_get_robust_list",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "int", Name: "pid"},
			{Type: "struct robust_list_head **", Name: "head_ptr"},
			{Type: "size_t *", Name: "len_ptr"},
		},
	})
	if r.Kind != KindNull {
		t.Fatalf("get_robust_list: got kind %d, want KindNull (pid arg must not be treated as fd)", r.Kind)
	}

	// set_robust_list takes a userspace head pointer and a length, no fd/path.
	s := ClassifyFormat(&Format{
		Name: "sys_enter_set_robust_list",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "struct robust_list_head *", Name: "head"},
			{Type: "size_t", Name: "len"},
		},
	})
	if s.Kind != KindNull {
		t.Fatalf("set_robust_list: got kind %d, want KindNull", s.Kind)
	}

	// Both syscalls are FamilyMisc, sharing the family with their per-thread
	// sibling rseq (and NOT promoted to FamilyIPC like the futex_* primitives).
	for _, name := range []string{
		"sys_enter_get_robust_list",
		"sys_enter_set_robust_list",
		"sys_enter_rseq",
	} {
		if fam := ClassifySyscallFamily(name); fam != FamilyMisc {
			t.Errorf("%s: got family %s, want FamilyMisc", name, fam)
		}
	}

	// Contrast: the futex_* siblings ARE classified IPC, so the robust-list pair
	// is deliberately NOT lumped in with them at the family level.
	if fam := ClassifySyscallFamily("sys_enter_futex"); fam != FamilyIPC {
		t.Errorf("futex: got family %s, want FamilyIPC (contrast case)", fam)
	}

	// Returns: both exits are UNCLASSIFIED (0/-1, no byte transfer).
	for _, name := range []string{"get_robust_list", "set_robust_list"} {
		if got := ClassifyRet("sys_exit_" + name); got != Unclassified {
			t.Errorf("ClassifyRet(sys_exit_%s) = %q, want UNCLASSIFIED", name, got)
		}
	}
}

// TestClassifyRecvmsgReadByteCount is a lock-in regression test for the
// recvmsg(2) audit. The syscall signature is:
//
//	ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
//
// args[0] is a socket file descriptor (the real kernel tracepoint format names
// the first field "fd"), msg is a userspace output pointer, and flags is an int.
// On success recvmsg returns the NUMBER OF BYTES RECEIVED, so its exit must be
// READ_CLASSIFIED — those bytes are counted as read, exactly like the
// recvfrom/recv/read/readv siblings, and never as a write.
//
// The invariants pinned here:
//   - enter classifies as KindFd off the first "fd" field (sockfd is an fd),
//   - family is Network (matches sendmsg/recvfrom/socket siblings),
//   - return classifies as READ_CLASSIFIED (bytes-received → read).
//
// Contrast cases guard against the two easy mistakes: sendmsg is the write-side
// sibling (WRITE_CLASSIFIED, never read), and recvmmsg is the batch variant
// whose per-message byte counts cannot be derived from its scalar return value
// (it returns a message count), so it is deliberately deferred to UNCLASSIFIED
// rather than READ_CLASSIFIED.
func TestClassifyRecvmsgReadByteCount(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_recvmsg: int fd, struct user_msghdr *msg, unsigned int flags.
	recvmsg := ClassifyFormat(&Format{
		Name: "sys_enter_recvmsg",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "int", Name: "fd"},
			{Type: "struct user_msghdr *", Name: "msg"},
			{Type: "unsigned int", Name: "flags"},
		},
	})
	if recvmsg.Kind != KindFd {
		t.Fatalf("recvmsg: got kind %d, want KindFd (sockfd at args[0] is an fd)", recvmsg.Kind)
	}

	if fam := ClassifySyscallFamily("sys_enter_recvmsg"); fam != FamilyNetwork {
		t.Fatalf("recvmsg: got family %s, want FamilyNetwork", fam)
	}

	// Return value is a byte count of data received → counted as read.
	if got := ClassifyRet("sys_exit_recvmsg"); got != ReadClassified {
		t.Fatalf("recvmsg: ClassifyRet = %q, want READ_CLASSIFIED (return is bytes received)", got)
	}

	// sendmsg is the write-side sibling; it must never be a read.
	if got := ClassifyRet("sys_exit_sendmsg"); got != WriteClassified {
		t.Fatalf("sendmsg: ClassifyRet = %q, want WRITE_CLASSIFIED", got)
	}

	// recvmmsg is the batch variant: its scalar return is a message count, not a
	// byte count, so it defers byte classification (UNCLASSIFIED) rather than
	// being mislabeled as a read.
	if got := ClassifyRet("sys_exit_recvmmsg"); got != Unclassified {
		t.Fatalf("recvmmsg: ClassifyRet = %q, want UNCLASSIFIED (batch return is not a byte count)", got)
	}

	// The single-message read siblings all count their return as bytes read.
	for _, name := range []string{
		"sys_exit_recvfrom",
		"sys_exit_read",
		"sys_exit_readv",
	} {
		if got := ClassifyRet(name); got != ReadClassified {
			t.Errorf("%s: ClassifyRet = %q, want READ_CLASSIFIED", name, got)
		}
	}

	// All read/write message-socket siblings share the Network family.
	for _, name := range []string{
		"sys_enter_sendmsg",
		"sys_enter_recvmmsg",
		"sys_enter_recvfrom",
	} {
		if fam := ClassifySyscallFamily(name); fam != FamilyNetwork {
			t.Errorf("%s: got family %s, want FamilyNetwork", name, fam)
		}
	}
}

// TestClassifySendmsgWriteByteCount is a lock-in regression test for the
// sendmsg(2) audit. The syscall signature is:
//
//	ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
//
// args[0] is a socket file descriptor (the real kernel tracepoint format names
// the first field "fd"), msg is a userspace input pointer, and flags is an int.
// On success sendmsg returns the NUMBER OF BYTES SENT, so its exit must be
// WRITE_CLASSIFIED — those bytes are counted as written, exactly like the
// send/sendto/write siblings, and never as a read.
//
// The invariants pinned here:
//   - enter classifies as KindFd off the first "fd" field (sockfd is an fd),
//   - family is Network (matches sendto/recvfrom/recvmsg/socket siblings),
//   - return classifies as WRITE_CLASSIFIED (bytes-sent → written).
//
// Contrast cases guard against the two easy mistakes: recvmsg is the read-side
// sibling (READ_CLASSIFIED, never write), and sendmmsg is the batch variant
// whose per-message byte counts cannot be derived from its scalar return value,
// so it is deliberately deferred to UNCLASSIFIED rather than WRITE_CLASSIFIED.
func TestClassifySendmsgWriteByteCount(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_sendmsg: int fd, struct user_msghdr *msg, unsigned int flags.
	sendmsg := ClassifyFormat(&Format{
		Name: "sys_enter_sendmsg",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "int", Name: "fd"},
			{Type: "struct user_msghdr *", Name: "msg"},
			{Type: "unsigned int", Name: "flags"},
		},
	})
	if sendmsg.Kind != KindFd {
		t.Fatalf("sendmsg: got kind %d, want KindFd (sockfd at args[0] is an fd)", sendmsg.Kind)
	}

	if fam := ClassifySyscallFamily("sys_enter_sendmsg"); fam != FamilyNetwork {
		t.Fatalf("sendmsg: got family %s, want FamilyNetwork", fam)
	}

	// Return value is a byte count of data sent → counted as written.
	if got := ClassifyRet("sys_exit_sendmsg"); got != WriteClassified {
		t.Fatalf("sendmsg: ClassifyRet = %q, want WRITE_CLASSIFIED (return is bytes sent)", got)
	}

	// recvmsg is the read-side sibling; it must never be a write.
	if got := ClassifyRet("sys_exit_recvmsg"); got != ReadClassified {
		t.Fatalf("recvmsg: ClassifyRet = %q, want READ_CLASSIFIED", got)
	}

	// sendmmsg is the batch variant: its scalar return is a message count, not a
	// byte count, so it defers byte classification (UNCLASSIFIED) rather than
	// being mislabeled as a write.
	if got := ClassifyRet("sys_exit_sendmmsg"); got != Unclassified {
		t.Fatalf("sendmmsg: ClassifyRet = %q, want UNCLASSIFIED (batch return is not a byte count)", got)
	}

	// All three send/recv message siblings share the Network family.
	for _, name := range []string{
		"sys_enter_recvmsg",
		"sys_enter_sendmmsg",
		"sys_enter_sendto",
	} {
		if fam := ClassifySyscallFamily(name); fam != FamilyNetwork {
			t.Errorf("%s: got family %s, want FamilyNetwork", name, fam)
		}
	}
}

// TestClassifyPwritev2WriteByteCount locks in the classification of the
// pwritev2(2) audit. The syscall signature is:
//
//	ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
//	                 off_t offset, int flags)
//
// args[0] is the file descriptor written to (the real kernel tracepoint format
// names the first field "fd"), iov/iovcnt describe the gather buffers, offset is
// the file position, and flags is an int (RWF_*). On success pwritev2 returns
// the NUMBER OF BYTES WRITTEN, so its exit must be WRITE_CLASSIFIED — those
// bytes are counted as written, exactly like the pwritev/writev/write/pwrite64
// siblings, and never as a read.
//
// The invariants pinned here:
//   - enter classifies as KindFd off the first "fd" field (fd at args[0]),
//   - family is FS (matches pwritev/writev/pwrite64/preadv2 file-IO siblings),
//   - return classifies as WRITE_CLASSIFIED (bytes-written → written).
//
// Contrast case guards the easy off-by-one mistake: preadv2 is the read-side
// sibling (READ_CLASSIFIED, never write). The whole p/readv/writev family is
// asserted together so a stray reclassification of any sibling trips the test.
func TestClassifyPwritev2WriteByteCount(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_pwritev2: int fd, struct iovec *vec, unsigned long vlen,
	// unsigned long pos_l, unsigned long pos_h, rwf_t flags.
	pwritev2 := ClassifyFormat(&Format{
		Name: "sys_enter_pwritev2",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "unsigned long", Name: "fd"},
			{Type: "const struct iovec *", Name: "vec"},
			{Type: "unsigned long", Name: "vlen"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
			{Type: "rwf_t", Name: "flags"},
		},
	})
	if pwritev2.Kind != KindFd {
		t.Fatalf("pwritev2: got kind %d, want KindFd (fd at args[0])", pwritev2.Kind)
	}

	if fam := ClassifySyscallFamily("sys_enter_pwritev2"); fam != FamilyFS {
		t.Fatalf("pwritev2: got family %s, want FamilyFS", fam)
	}

	// Return value is a byte count of data written → counted as written.
	if got := ClassifyRet("sys_exit_pwritev2"); got != WriteClassified {
		t.Fatalf("pwritev2: ClassifyRet = %q, want WRITE_CLASSIFIED (return is bytes written)", got)
	}

	// preadv2 is the read-side sibling; it must never be a write.
	if got := ClassifyRet("sys_exit_preadv2"); got != ReadClassified {
		t.Fatalf("preadv2: ClassifyRet = %q, want READ_CLASSIFIED", got)
	}

	// All write-side vectored/positional siblings count their byte-count return
	// as written; assert the whole group so a stray reclassification trips here.
	for _, name := range []string{
		"sys_exit_pwritev",
		"sys_exit_writev",
		"sys_exit_write",
		"sys_exit_pwrite64",
	} {
		if got := ClassifyRet(name); got != WriteClassified {
			t.Errorf("%s: ClassifyRet = %q, want WRITE_CLASSIFIED", name, got)
		}
	}

	// All read-side siblings stay READ_CLASSIFIED (off-by-one guard).
	for _, name := range []string{
		"sys_exit_preadv",
		"sys_exit_readv",
		"sys_exit_read",
		"sys_exit_pread64",
	} {
		if got := ClassifyRet(name); got != ReadClassified {
			t.Errorf("%s: ClassifyRet = %q, want READ_CLASSIFIED", name, got)
		}
	}

	// The whole p/readv/writev family shares the FS family.
	for _, name := range []string{
		"sys_enter_pwritev",
		"sys_enter_writev",
		"sys_enter_write",
		"sys_enter_pwrite64",
		"sys_enter_preadv2",
		"sys_enter_preadv",
		"sys_enter_readv",
		"sys_enter_read",
		"sys_enter_pread64",
	} {
		if fam := ClassifySyscallFamily(name); fam != FamilyFS {
			t.Errorf("%s: got family %s, want FamilyFS", name, fam)
		}
	}
}

// TestClassifyPwritevWriteByteCount locks in the classification of the
// pwritev(2) audit. The syscall signature is:
//
//	ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
//
// pwritev gathers iovcnt buffers and writes them to fd at the absolute file
// offset (it does NOT advance the file offset, and unlike pwritev2 it takes no
// flags argument — that flags field is the only structural difference from its
// pwritev2 sibling). args[0] is the file descriptor written to (the real kernel
// tracepoint format names the first field "fd"; vec/vlen describe the gather
// buffers and pos_l/pos_h carry the 64-bit offset). On success pwritev returns
// the NUMBER OF BYTES WRITTEN, so its exit must be WRITE_CLASSIFIED — those
// bytes are counted as written, exactly like the write/pwrite64/writev/pwritev2
// siblings, and never as a read.
//
// The invariants pinned here:
//   - enter classifies as KindFd off the first "fd" field (fd at args[0]),
//   - family is FS (matches write/pwrite64/writev/pwritev2 file-IO siblings),
//   - return classifies as WRITE_CLASSIFIED (bytes-written → written).
//
// Contrast case guards the easy off-by-one mistake in the read/write tables:
// preadv is the read-side vectored+positional counterpart (READ_CLASSIFIED,
// never write). Both directions are asserted together so a stray
// reclassification of either side trips the test, and the write-side return is
// explicitly checked not to leak into the transfer/unclassified buckets.
func TestClassifyPwritevWriteByteCount(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_pwritev: unsigned long fd, const struct iovec *vec,
	// unsigned long vlen, unsigned long pos_l, unsigned long pos_h.
	// (No flags field — that is what distinguishes pwritev from pwritev2.)
	pwritev := ClassifyFormat(&Format{
		Name: "sys_enter_pwritev",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "unsigned long", Name: "fd"},
			{Type: "const struct iovec *", Name: "vec"},
			{Type: "unsigned long", Name: "vlen"},
			{Type: "unsigned long", Name: "pos_l"},
			{Type: "unsigned long", Name: "pos_h"},
		},
	})
	if pwritev.Kind != KindFd {
		t.Fatalf("pwritev: got kind %d, want KindFd (fd at args[0])", pwritev.Kind)
	}

	if fam := ClassifySyscallFamily("sys_enter_pwritev"); fam != FamilyFS {
		t.Fatalf("pwritev: got family %s, want FamilyFS", fam)
	}

	// Return value is a byte count of data written → counted as written.
	if got := ClassifyRet("sys_exit_pwritev"); got != WriteClassified {
		t.Fatalf("pwritev: ClassifyRet = %q, want WRITE_CLASSIFIED (return is bytes written)", got)
	}

	// preadv is the read-side vectored+positional counterpart; it must never be
	// a write (off-by-one guard in the read/write classification tables).
	if got := ClassifyRet("sys_exit_preadv"); got != ReadClassified {
		t.Fatalf("preadv: ClassifyRet = %q, want READ_CLASSIFIED", got)
	}

	// pwritev must not leak into the transfer (sendfile/splice style) bucket nor
	// be left unclassified — it is a plain write byte count.
	if got := ClassifyRet("sys_exit_pwritev"); got == TransferClassified || got == Unclassified {
		t.Fatalf("pwritev: ClassifyRet = %q, want WRITE_CLASSIFIED, not transfer/unclassified", got)
	}

	// All vectored/positional write siblings count their byte-count return as
	// written; assert the group so a stray reclassification trips here.
	for _, name := range []string{
		"sys_exit_pwritev",
		"sys_exit_pwritev2",
		"sys_exit_writev",
		"sys_exit_write",
		"sys_exit_pwrite64",
	} {
		if got := ClassifyRet(name); got != WriteClassified {
			t.Errorf("%s: ClassifyRet = %q, want WRITE_CLASSIFIED", name, got)
		}
	}

	// All read-side siblings stay READ_CLASSIFIED (off-by-one guard).
	for _, name := range []string{
		"sys_exit_preadv",
		"sys_exit_preadv2",
		"sys_exit_readv",
		"sys_exit_read",
		"sys_exit_pread64",
	} {
		if got := ClassifyRet(name); got != ReadClassified {
			t.Errorf("%s: ClassifyRet = %q, want READ_CLASSIFIED", name, got)
		}
	}

	// The fd-bearing vectored/positional siblings all share KindFd at args[0]
	// and the FS family; pin both enter sides so a kind/family drift trips here.
	for _, name := range []string{
		"sys_enter_pwritev",
		"sys_enter_pwritev2",
		"sys_enter_writev",
		"sys_enter_write",
		"sys_enter_pwrite64",
		"sys_enter_preadv",
		"sys_enter_preadv2",
		"sys_enter_readv",
		"sys_enter_read",
		"sys_enter_pread64",
	} {
		if fam := ClassifySyscallFamily(name); fam != FamilyFS {
			t.Errorf("%s: got family %s, want FamilyFS", name, fam)
		}
	}
}

// TestClassifyPwrite64WriteByteCount locks in the classification of the
// pwrite64(2) audit. The syscall signature is:
//
//	ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset)
//
// args[0] is the file descriptor written to (the kernel tracepoint format names
// the first field "fd"), buf/count describe the source buffer, and offset is the
// absolute file position (pwrite64 does NOT advance the file offset). On success
// pwrite64 returns the NUMBER OF BYTES WRITTEN, so its exit must be
// WRITE_CLASSIFIED — those bytes are counted as written, exactly like the
// write/pwrite/pwritev/pwritev2 siblings, and never as a read.
//
// The invariants pinned here:
//   - enter classifies as KindFd off the first "fd" field (fd at args[0]),
//   - family is FS (matches write/pread64/pwritev file-IO siblings),
//   - return classifies as WRITE_CLASSIFIED (bytes-written → written).
//
// Contrast case guards the easy off-by-one mistake in the read/write tables:
// pread64 is the read-side positional counterpart (READ_CLASSIFIED, never
// write). Both directions are asserted together so a stray reclassification of
// either side trips the test.
func TestClassifyPwrite64WriteByteCount(t *testing.T) {
	// Field layout mirrors the actual kernel tracepoint format for
	// sys_enter_pwrite64: unsigned int fd, const char *buf, size_t count,
	// loff_t pos.
	pwrite64 := ClassifyFormat(&Format{
		Name: "sys_enter_pwrite64",
		ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "unsigned int", Name: "fd"},
			{Type: "const char *", Name: "buf"},
			{Type: "size_t", Name: "count"},
			{Type: "loff_t", Name: "pos"},
		},
	})
	if pwrite64.Kind != KindFd {
		t.Fatalf("pwrite64: got kind %d, want KindFd (fd at args[0])", pwrite64.Kind)
	}

	if fam := ClassifySyscallFamily("sys_enter_pwrite64"); fam != FamilyFS {
		t.Fatalf("pwrite64: got family %s, want FamilyFS", fam)
	}

	// Return value is a byte count of data written → counted as written.
	if got := ClassifyRet("sys_exit_pwrite64"); got != WriteClassified {
		t.Fatalf("pwrite64: ClassifyRet = %q, want WRITE_CLASSIFIED (return is bytes written)", got)
	}

	// pread64 is the read-side positional counterpart; it must never be a
	// write (off-by-one guard in the read/write classification tables).
	if got := ClassifyRet("sys_exit_pread64"); got != ReadClassified {
		t.Fatalf("pread64: ClassifyRet = %q, want READ_CLASSIFIED", got)
	}

	// pwrite64 must not be misclassified as a transfer (sendfile/splice style)
	// nor left unclassified — it is a plain write byte count.
	if got := ClassifyRet("sys_exit_pwrite64"); got == TransferClassified || got == Unclassified {
		t.Fatalf("pwrite64: ClassifyRet = %q, want WRITE_CLASSIFIED, not transfer/unclassified", got)
	}

	// All positional/plain write siblings count their byte-count return as
	// written; assert the group so a stray reclassification trips here.
	// (There is no separate sys_exit_pwrite tracepoint on Linux: the glibc
	// pwrite() wrapper dispatches the pwrite64 syscall, so only pwrite64 has a
	// tracepoint to classify.)
	for _, name := range []string{
		"sys_exit_pwrite64",
		"sys_exit_pwritev",
		"sys_exit_pwritev2",
		"sys_exit_write",
	} {
		if got := ClassifyRet(name); got != WriteClassified {
			t.Errorf("%s: ClassifyRet = %q, want WRITE_CLASSIFIED", name, got)
		}
	}

	// The fd-bearing positional siblings all share KindFd at args[0] and the
	// FS family; pin both enter sides so a kind/family drift trips here.
	for _, name := range []string{
		"sys_enter_pwrite64",
		"sys_enter_pread64",
		"sys_enter_write",
		"sys_enter_read",
	} {
		if fam := ClassifySyscallFamily(name); fam != FamilyFS {
			t.Errorf("%s: got family %s, want FamilyFS", name, fam)
		}
	}
}

func mustParseAll(t *testing.T, data string) []Format {
	t.Helper()
	formats, err := ParseFormats(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseFormats failed: %v", err)
	}
	return formats
}
