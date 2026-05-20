package generate

import (
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

func TestClassifyPathnameExecve(t *testing.T) {
	r := classifyFromData(t, FormatExecve)
	if r.Kind != KindPathname {
		t.Errorf("execve: got kind %d, want KindPathname", r.Kind)
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

func TestClassifyKillRequiresGenerationFallback(t *testing.T) {
	r := classifyFromData(t, FormatKill)
	if r.Kind != KindNone {
		t.Errorf("kill: got kind %d, want KindNone before generation fallback", r.Kind)
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
		{"execve", FormatExecve, FormatExitExecve, KindPathname},
		{"accept", FormatAccept, FormatExitAccept, KindAccept},
		{"accept4", FormatAccept4, FormatExitAccept4, KindAccept},
		{"socket", FormatSocket, FormatExitSocket, KindSocket},
		{"socketpair", FormatSocketpair, FormatExitSocketpair, KindSocketpair},
		{"pipe", FormatPipe, FormatExitPipe, KindPipe},
		{"pipe2", FormatPipe2, FormatExitPipe2, KindPipe},
		{"eventfd", FormatEventfd, FormatExitEventfd, KindEventfd},
		{"eventfd2", FormatEventfd2, FormatExitEventfd2, KindEventfd},
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
		{"nanosleep", FormatNanosleep, FormatExitNanosleep, KindSleep},
		{"clock_nanosleep", FormatClockNanosleep, FormatExitClockNanosleep, KindSleep},
		{"kill", FormatKill, FormatExitKill, KindNull},
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
		{"kill", FormatKill, FormatExitKill, FamilySignals},
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
			if !strings.Contains(output, `SEC("tracepoint/syscalls/sys_exit_`+tt.name+`")`) {
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

func mustParseAll(t *testing.T, data string) []Format {
	t.Helper()
	formats, err := ParseFormats(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseFormats failed: %v", err)
	}
	return formats
}
