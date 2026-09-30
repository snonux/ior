package tracepoints

import (
	"testing"

	"ior/internal/types"
)

func TestSyscallFamilyLookup(t *testing.T) {
	tests := []struct {
		name   string
		want   types.SyscallFamily
		wantOK bool
	}{
		{"openat", types.FamilyFS, true},
		{" Socket ", types.FamilyNetwork, true},
		{"nanosleep", types.FamilyTime, true},
		{"", "", false},
		{"sys_enter_openat", "", false}, // bare names only
		{"no_such_syscall", "", false},
	}
	for _, tt := range tests {
		got, ok := SyscallFamily(tt.name)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("SyscallFamily(%q) = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.wantOK)
		}
	}
}

// Every syscall tracepoint ior can attach must resolve to a family, so the
// TUI family view accounts for every probe (none silently lumped into Misc).
func TestEveryTracepointHasAFamily(t *testing.T) {
	for _, tp := range List {
		syscall, ok := SyscallNameFromTracepoint(tp)
		if !ok {
			continue
		}
		if _, ok := SyscallFamily(syscall); !ok {
			t.Errorf("tracepoint %s: syscall %q has no family", tp, syscall)
		}
	}
}

func TestSelectorForSyscallsAttachesExactlyTheList(t *testing.T) {
	sel := SelectorForSyscalls([]string{"openat", "socket"})
	for tp, want := range map[string]bool{
		"sys_enter_openat": true, "sys_exit_openat": true, "sys_enter_socket": true,
		"sys_enter_read": false, "sched_process_exec": false,
	} {
		if got := sel.ShouldAttach(tp); got != want {
			t.Errorf("ShouldAttach(%s) = %v, want %v", tp, got, want)
		}
	}
	// An empty selection is "nothing attached", not "no restriction".
	for _, empty := range [][]string{nil, {}} {
		if SelectorForSyscalls(empty).ShouldAttach("sys_enter_openat") {
			t.Errorf("SelectorForSyscalls(%v) attaches openat, want nothing", empty)
		}
	}
}
