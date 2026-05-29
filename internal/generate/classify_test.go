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

func TestClassifyNullGetcwd(t *testing.T) {
	r := classifyFromData(t, FormatGetcwd)
	if r.Kind != KindNull {
		t.Errorf("getcwd: got kind %d, want KindNull", r.Kind)
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

func TestClassifyKillExplicitNull(t *testing.T) {
	r := classifyFromData(t, FormatKill)
	if r.Kind != KindNull {
		t.Errorf("kill: got kind %d, want KindNull", r.Kind)
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
		{"sendfile64", "struct null_event", "TRANSFER_CLASSIFIED"},
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

func mustParseAll(t *testing.T, data string) []Format {
	t.Helper()
	formats, err := ParseFormats(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseFormats failed: %v", err)
	}
	return formats
}
