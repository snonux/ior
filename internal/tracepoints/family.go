package tracepoints

import (
	"strings"

	"ior/internal/types"
)

// SyscallFamily returns the attach-time family of a bare syscall name (for
// example "openat" -> FS), the same table -trace-families and
// -no-trace-families select from. ok is false for a name the generated table
// does not know.
func SyscallFamily(syscall string) (types.SyscallFamily, bool) {
	family, ok := syscallFamilies[strings.ToLower(strings.TrimSpace(syscall))]
	if !ok {
		return "", false
	}
	return types.SyscallFamily(family), true
}

// SelectorForSyscalls returns a Selector that attaches exactly the given bare
// syscall names and nothing else. An empty (or nil) list attaches nothing.
//
// The TUI uses it to carry the probe set the user attached or detached at
// runtime (probes modal) into the next trace session, so a restart after a
// PID/TID reselect or a filter change keeps that set instead of falling back
// to the startup -trace-* / -tps selection.
func SelectorForSyscalls(syscalls []string) Selector {
	allow := make(map[string]struct{}, len(syscalls))
	for _, syscall := range syscalls {
		allow[syscall] = struct{}{}
	}
	return Selector{Syscalls: allow, RestrictSyscalls: true}
}
