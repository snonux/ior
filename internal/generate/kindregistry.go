package generate

// kindMeta holds static metadata for a TracepointKind. Adding a new kind
// only requires registering an entry here — no switch statements need to be
// updated elsewhere (Open/Closed Principle).
type kindMeta struct {
	// structName is the C struct name used in generated BPF handlers, e.g. "fd_event".
	structName string
	// enterAccepted reports whether this kind is valid for a syscall-enter tracepoint.
	// Kinds that are exit-only (e.g. KindRet) must not appear on enter.
	enterAccepted bool
	// recoversFilename reports whether this enter kind stashes its user-space
	// path pointer when bpf_probe_read_user_str faults, so that the matching
	// exit handler re-reads the string once the kernel has faulted the page in
	// (see internal/c/filter.c). Every kind that captures a path does: the open
	// kinds and named descriptor creators, where a lost name also poisons the
	// fd table for every later read/write/close on the descriptor, and the
	// pathname, fd-pathname, name and two-fd-names kinds (stat, access,
	// unlink, inotify, rename, move_mount, ...), where a lost name leaves the
	// row's file empty so -path cannot match it. The one kind that captures a
	// path but is not listed is exec, deliberately: a successful exec replaces
	// the address space the stashed pointer belonged to.
	recoversFilename bool
	// recoversSecondFilename reports whether the kind also recovers a second
	// path (the newname of the rename/link family, move_mount's to_pathname).
	// It implies recoversFilename and uses its own stash slot and fixup slot,
	// because either read can fault independently of the other.
	recoversSecondFilename bool
}

// kindRegistry maps every known TracepointKind to its static metadata.
// To add a new syscall classification, add a single entry here; the rest of
// the code (isEnterRejected, eventStructName, eventTypeConstant) picks it up
// automatically via lookupKind.
var kindRegistry = map[TracepointKind]kindMeta{
	KindFd:             {structName: "fd_event", enterAccepted: true},
	KindFdSize:         {structName: "fd_size_event", enterAccepted: true},
	KindOpen:           {structName: "open_event", enterAccepted: true, recoversFilename: true},
	KindMqOpen:         {structName: "open_event", enterAccepted: true, recoversFilename: true},
	KindOpenTree:       {structName: "open_event", enterAccepted: true, recoversFilename: true},
	KindExec:           {structName: "exec_event", enterAccepted: true},
	KindPathname:       {structName: "path_event", enterAccepted: true, recoversFilename: true},
	KindFdPathname:     {structName: "fd_path_event", enterAccepted: true, recoversFilename: true},
	KindName:           {structName: "name_event", enterAccepted: true, recoversFilename: true, recoversSecondFilename: true},
	KindRet:            {structName: "ret_event", enterAccepted: false},
	KindFcntl:          {structName: "fcntl_event", enterAccepted: true},
	KindNull:           {structName: "null_event", enterAccepted: true},
	KindDup3:           {structName: "dup3_event", enterAccepted: true},
	KindOpenByHandleAt: {structName: "open_by_handle_at_event", enterAccepted: true},
	KindSocket:         {structName: "socket_event", enterAccepted: true},
	KindSocketpair:     {structName: "socketpair_event", enterAccepted: true},
	KindAccept:         {structName: "accept_event", enterAccepted: true},
	KindPipe:           {structName: "pipe_event", enterAccepted: true},
	KindEventfd:        {structName: "eventfd_event", enterAccepted: true},
	KindNamedEventfd:   {structName: "eventfd_name_event", enterAccepted: true, recoversFilename: true},
	KindPidfd:          {structName: "eventfd_event", enterAccepted: true},
	KindEpollCtl:       {structName: "epoll_ctl_event", enterAccepted: true},
	KindTwoFd:          {structName: "two_fd_event", enterAccepted: true},
	KindTwoFdNames:     {structName: "two_fd_names_event", enterAccepted: true, recoversFilename: true, recoversSecondFilename: true},
	KindPoll:           {structName: "poll_event", enterAccepted: true},
	KindMem:            {structName: "mem_event", enterAccepted: true},
	KindMmap:           {structName: "mmap_event", enterAccepted: true},
	KindSleep:          {structName: "sleep_event", enterAccepted: true},
	KindKeyctl:         {structName: "keyctl_event", enterAccepted: true},
	KindPtrace:         {structName: "ptrace_event", enterAccepted: true},
	KindPerfOpen:       {structName: "perf_open_event", enterAccepted: true},
	KindSeccomp:        {structName: "null_event", enterAccepted: true},
	KindModule:         {structName: "null_event", enterAccepted: true},
	KindSysVId:         {structName: "null_event", enterAccepted: true},
	KindSysVOp:         {structName: "null_event", enterAccepted: true},
	KindProc:           {structName: "null_event", enterAccepted: true},
	KindBpf:            {structName: "bpf_event", enterAccepted: true},
	KindFutex:          {structName: "null_event", enterAccepted: true},
	KindPrctl:          {structName: "null_event", enterAccepted: true},
	KindTimerObj:       {structName: "null_event", enterAccepted: true},
	KindIoUringFd:      {structName: "fcntl_event", enterAccepted: true},
	KindIoUringSetup:   {structName: "fcntl_event", enterAccepted: true},
	// KindNone is intentionally absent: it represents "unclassified" and is
	// never enter-accepted. lookupKind returns the zero kindMeta (enterAccepted=false)
	// for any unregistered kind, so KindNone is implicitly rejected.
}

// kindRecoversFilename reports whether kind participates in the sys_exit
// filename recovery described in internal/c/filter.c.
func kindRecoversFilename(kind TracepointKind) bool {
	return lookupKind(kind).recoversFilename
}

// kindRecoversSecondFilename reports whether kind also recovers a second path
// (newname) through its own stash and fixup slot.
func kindRecoversSecondFilename(kind TracepointKind) bool {
	return lookupKind(kind).recoversSecondFilename
}

// lookupKind returns the metadata for kind. If kind is not registered (e.g.
// KindNone or an unknown value), it returns a zero kindMeta whose structName
// is "unknown_event" and enterAccepted is false.
func lookupKind(kind TracepointKind) kindMeta {
	if m, ok := kindRegistry[kind]; ok {
		return m
	}
	return kindMeta{structName: "unknown_event", enterAccepted: false}
}
