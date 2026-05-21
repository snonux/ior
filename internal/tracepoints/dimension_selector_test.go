package tracepoints

import (
	"strings"
	"testing"
)

func TestParseSelectorWithDimensionsDefaultFSOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected FS syscall openat to be attached by default")
	}
	if sel.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected non-FS syscall nanosleep to be excluded by default")
	}
}

func TestParseSelectorWithDimensionsFamilyOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceFamilies: "Time",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep to be attached when Time family is enabled")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only Time family is enabled")
	}
}

func TestParseSelectorWithDimensionsKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "sleep",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep to be attached for sleep kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only sleep kind is enabled")
	}
}

func TestParseSelectorWithDimensionsPidfdKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "pidfd",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_pidfd_open") {
		t.Fatal("expected pidfd_open to be attached for pidfd kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only pidfd kind is enabled")
	}
}

func TestParseSelectorWithDimensionsFdKindIncludesProcessMadvise(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "fd",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_process_madvise") {
		t.Fatal("expected process_madvise to be attached for fd kind")
	}
	if sel.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep to be excluded when only fd kind is enabled")
	}
}

func TestParseSelectorWithDimensionsEventfdKindIncludesEpollCreate(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "eventfd",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_epoll_create1") {
		t.Fatal("expected epoll_create1 to be attached for eventfd kind")
	}
	if sel.ShouldAttach("sys_enter_epoll_wait") {
		t.Fatal("expected epoll_wait to be excluded when only eventfd kind is enabled")
	}
}

func TestParseSelectorWithDimensionsMemKindIncludesMlock(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "mem",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_mlock") {
		t.Fatal("expected mlock to be attached for mem kind")
	}
	if !sel.ShouldAttach("sys_enter_mprotect") {
		t.Fatal("expected mprotect to be attached for mem kind")
	}
	if sel.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep to be excluded when only mem kind is enabled")
	}
}

func TestParseSelectorWithDimensionsSeccompKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "seccomp",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_seccomp") {
		t.Fatal("expected seccomp to be attached for seccomp kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only seccomp kind is enabled")
	}
}

func TestParseSelectorWithDimensionsSysVOpKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "sysv-op",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_msgsnd") {
		t.Fatal("expected msgsnd to be attached for sysv-op kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only sysv-op kind is enabled")
	}
}

func TestParseSelectorWithDimensionsProcKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "proc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_clone3") {
		t.Fatal("expected clone3 to be attached for proc kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only proc kind is enabled")
	}
}

func TestParseSelectorWithDimensionsBpfKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "bpf",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_bpf") {
		t.Fatal("expected bpf to be attached for bpf kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only bpf kind is enabled")
	}
}

func TestParseSelectorWithDimensionsFutexKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "futex",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_futex_waitv") {
		t.Fatal("expected futex_waitv to be attached for futex kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only futex kind is enabled")
	}
}

func TestParseSelectorWithDimensionsPrctlKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "prctl",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_prctl") {
		t.Fatal("expected prctl to be attached for prctl kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only prctl kind is enabled")
	}
}

func TestParseSelectorWithDimensionsTimerObjKindOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "timer-obj",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_timer_settime") {
		t.Fatal("expected timer_settime to be attached for timer-obj kind")
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded when only timer-obj kind is enabled")
	}
}

func TestParseSelectorWithDimensionsSyscallOnly(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceSyscalls: "openat",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_openat") || !sel.ShouldAttach("sys_exit_openat") {
		t.Fatal("expected both openat enter/exit tracepoints to be attached")
	}
	if sel.ShouldAttach("sys_enter_write") {
		t.Fatal("expected write to be excluded when only openat is selected")
	}
}

func TestParseSelectorWithDimensionsUnionSemantics(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceFamilies: "Time",
		TraceSyscalls: "openat",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat from syscall selector")
	}
	if !sel.ShouldAttach("sys_enter_nanosleep") {
		t.Fatal("expected nanosleep from family selector")
	}
}

func TestParseSelectorWithDimensionsExclusionsOverridePositives(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceFamilies:   "FS",
		NoTraceSyscalls: "openat",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to be excluded by -no-trace-syscalls")
	}
	if !sel.ShouldAttach("sys_enter_read") {
		t.Fatal("expected other FS syscall (read) to remain attached")
	}
}

func TestParseSelectorWithDimensionsRegexStillApplies(t *testing.T) {
	sel, err := ParseSelectorWithDimensions("^sys_enter_openat$,^sys_exit_openat$", "", DimensionSelectorConfig{
		TraceFamilies: "FS",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected openat to pass regex+dimension filters")
	}
	if sel.ShouldAttach("sys_enter_read") {
		t.Fatal("expected read to fail regex attach filters")
	}
}

func TestParseSelectorWithDimensionsRejectsInvalidFamily(t *testing.T) {
	_, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceFamilies: "Nope",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid syscall family") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSelectorWithDimensionsRejectsInvalidKind(t *testing.T) {
	_, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceKinds: "not-a-kind",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid syscall kind") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSelectorWithDimensionsRejectsInvalidSyscall(t *testing.T) {
	_, err := ParseSelectorWithDimensions("", "", DimensionSelectorConfig{
		TraceSyscalls: "not_a_syscall",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid syscall in trace selector") {
		t.Fatalf("unexpected error: %v", err)
	}
}
