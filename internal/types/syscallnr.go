package types

// SyscallNumber returns the number the running architecture gives the syscall
// of this tracepoint, enter or exit, and whether it is known: the trace IDs
// are tracepoint event IDs, which say nothing about it, so the number comes
// from a table by name (syscallNumbers), which exists for x86_64 only.
//
// The event loop asks for it to recognise a call a seccomp filter trapped
// (SECCOMP_RET_TRAP): the kernel skips such a call and rolls the return
// register back to the syscall number, so its sys_exit record carries the
// call's own number as the return value (internal/eventloop_losthalves.go).
func (s TraceId) SyscallNumber() (int64, bool) {
	name, ok := traceId2Name[s]
	if !ok {
		return 0, false
	}
	nr, ok := syscallNumbers[name]
	return nr, ok
}
