package event

const maxErrno = int64(4095)

// Kernel-internal restart codes (include/linux/errno.h). When a signal
// interrupts a blocked syscall the handler returns one of these and the
// signal-delivery path either re-executes the syscall (a fresh sys_enter
// follows) or rewrites the value to -EINTR before user space sees it. The
// raw value is nevertheless visible at the sys_exit tracepoint, so ior sees
// an "exit" that user space never observes.
const (
	errRestartSys       = int64(512) // ERESTARTSYS
	errRestartNoIntr    = int64(513) // ERESTARTNOINTR
	errRestartNoHand    = int64(514) // ERESTARTNOHAND
	errRestartRestartBl = int64(516) // ERESTART_RESTARTBLOCK
)

// IsRestartRet reports whether ret is one of the kernel-internal restart
// codes (-ERESTARTSYS, -ERESTARTNOINTR, -ERESTARTNOHAND,
// -ERESTART_RESTARTBLOCK). Such a return means the call was interrupted by a
// signal and is about to be transparently restarted: it did not fail, and no
// user-visible result was produced. -515 (ENOIOCTLCMD) is deliberately not
// listed: it is a driver-internal code that the ioctl core maps to -ENOTTY,
// so it is not a restart marker.
func IsRestartRet(ret int64) bool {
	switch -ret {
	case errRestartSys, errRestartNoIntr, errRestartNoHand, errRestartRestartBl:
		return true
	}
	return false
}

// IsRestartBlockRet reports whether ret is -ERESTART_RESTARTBLOCK (-516), the
// one restart code whose continuation is a separate syscall: when no handler
// runs, the kernel re-enters the task through restart_syscall instead of
// re-executing the interrupted call, so restart_syscall is the only sys_enter
// that can resume it. The event loop folds that continuation into the
// interrupted row (task fs2, internal/eventloop_restart.go).
func IsRestartBlockRet(ret int64) bool {
	return ret == -errRestartRestartBl
}

// IsErrnoRet reports whether ret lies in the kernel's errno window, that is
// whether the call produced no result (the raw return is -MAX_ERRNO through
// -1). Other negative raw words can be successful returns from pointer- or
// offset-valued syscalls. This deliberately includes the restart codes: the
// interrupted call had no effect (no descriptor was created, no bytes moved),
// which is what the fd-tracking and byte-accounting callers need. Callers that
// count or flag *failures* must use IsErrorRet instead.
func IsErrnoRet(ret int64) bool {
	return ret >= -maxErrno && ret < 0
}

// IsErrorRet reports whether ret is a genuine syscall failure: an errno the
// program can observe. It is IsErrnoRet minus the restart codes, which are
// interruptions rather than errors. Use it for error counters, the is_error
// column and the errors-only filter.
func IsErrorRet(ret int64) bool {
	return IsErrnoRet(ret) && !IsRestartRet(ret)
}
