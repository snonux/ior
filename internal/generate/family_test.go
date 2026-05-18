package generate

import "testing"

func TestClassifySyscallFamily(t *testing.T) {
	tests := []struct {
		name string
		want SyscallFamily
	}{
		{"sys_enter_accept", FamilyNetwork},
		{"sys_exit_accept", FamilyNetwork},
		{"sys_enter_pipe2", FamilyIPC},
		{"sys_enter_munmap", FamilyMemory},
		{"sys_enter_execve", FamilyProcess},
		{"sys_enter_rt_sigaction", FamilySignals},
		{"sys_enter_clock_gettime", FamilyTime},
		{"sys_enter_sched_yield", FamilySched},
		{"sys_enter_openat", FamilyFS},
		{"sys_enter_epoll_wait", FamilyPolling},
		{"sys_enter_io_uring_enter", FamilyAIO},
		{"sys_enter_bpf", FamilySecurity},
		{"sys_enter_unlisted_future_syscall", FamilyMisc},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifySyscallFamily(tt.name); got != tt.want {
				t.Errorf("ClassifySyscallFamily(%q) = %s, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestParseFormatsTagsEveryFormatWithFamily(t *testing.T) {
	formats := mustParseAll(t, FormatRead+"\n"+FormatExitSocket+"\n"+FormatExitKill)

	tests := []struct {
		index int
		want  SyscallFamily
	}{
		{0, FamilyFS},
		{1, FamilyNetwork},
		{2, FamilySignals},
	}

	for _, tt := range tests {
		if got := formats[tt.index].Family; got != tt.want {
			t.Errorf("formats[%d].Family = %s, want %s", tt.index, got, tt.want)
		}
	}
}
