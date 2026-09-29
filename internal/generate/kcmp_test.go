package generate

import "testing"

func kcmpFormats() []Format {
	return []Format{
		{Name: "sys_enter_kcmp", ID: 417, ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"},
			{Type: "pid_t", Name: "pid1"}, {Type: "pid_t", Name: "pid2"},
			{Type: "int", Name: "type"}, {Type: "unsigned long", Name: "idx1"},
			{Type: "unsigned long", Name: "idx2"},
		}},
		{Name: "sys_exit_kcmp", ID: 416, ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"}, {Type: "long", Name: "ret"},
		}},
	}
}

func TestGeneratedKcmpCapturesOnlyFileIndicesAndTheirOwner(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatal(err)
	}
	generated := GenerateTracepointsC(kcmpFormats())
	for _, name := range []string{"sys_enter_kcmp", "sys_exit_kcmp"} {
		if handlerBody(t, generated, name) != handlerBody(t, artifact, name) {
			t.Errorf("%s committed handler differs from the generator", name)
		}
	}
	body := handlerBody(t, generated, "sys_enter_kcmp")
	// Literal expectations intentionally independent of twoFdOverrides:
	// changing the comparison guard, owner argument, casts or packing fails.
	for _, line := range []string{
		"ev->fd_a = (__u32)ctx->args[2] == 0 ? (__s32)ctx->args[3] : -1;",
		"ev->fd_b = (__u32)ctx->args[2] == 0 ? (__s32)ctx->args[4] : -1;",
		"ev->extra = ((__u64)(ior_kcmp_pid_is_current((__s32)ctx->args[0]) ? pid : 0) << 32) | (__u32)ctx->args[2];",
	} {
		requireContains(t, body, line)
	}

	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"task = (struct task_struct *)bpf_get_current_task();",
		"signal = BPF_CORE_READ(task, signal);",
		"tgid_pid = BPF_CORE_READ(signal, pids[PIDTYPE_TGID]);",
		"level = BPF_CORE_READ(tgid_pid, level);",
		"bpf_core_read(&tgid, sizeof(tgid), &tgid_pid->numbers[level].nr)",
		"return (__u32)pid1 == ior_current_namespace_tgid();",
	} {
		requireContains(t, filterC, line)
	}
}
