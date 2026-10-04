package generate

import (
	"fmt"
	"strings"
	"testing"
)

// checkEnterHookMatchesStash enforces the task 2s2 contract of the two enter
// hooks: ior_on_syscall_enter writes no enter state at rate 1, so a handler
// that stashes a pending filename onto that state (the stash is a no-op without
// an entry) must call ior_on_syscall_enter_stateful, and no other handler needs
// to pay for it. A returning enter handler calls exactly one of the two.
func checkEnterHookMatchesStash(name, body string) error {
	if !strings.HasPrefix(name, "sys_enter_") || strings.Contains(body, "ior_on_noreturn_syscall_enter(") {
		return nil
	}
	stashes := strings.Contains(body, "ior_stash_pending_filename")
	stateful := strings.Contains(body, "ior_on_syscall_enter_stateful(")
	plain := strings.Contains(body, "ior_on_syscall_enter(")
	switch {
	case stateful == plain:
		return fmt.Errorf("%s: want exactly one enter hook, stateful=%v plain=%v", name, stateful, plain)
	case stashes && !stateful:
		return fmt.Errorf("%s stashes a pending filename but uses the hook that writes no enter state at rate 1", name)
	case !stashes && stateful:
		return fmt.Errorf("%s uses the stateful enter hook without stashing anything", name)
	}
	return nil
}

func TestGeneratedEnterHooksMatchTheirStash(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	handlers := splitGeneratedHandlers(t, artifact)
	stateful := 0
	for name, body := range handlers {
		if err := checkEnterHookMatchesStash(name, body); err != nil {
			t.Error(err)
		}
		if strings.Contains(body, "ior_on_syscall_enter_stateful(") {
			stateful++
		}
	}
	if stateful == 0 {
		t.Error("no handler uses ior_on_syscall_enter_stateful: the path-capturing syscalls lost their enter state")
	}
}

// TestEnterHookCheckRejectsMismatches keeps the checker honest, and pins the
// fresh generator output for the three shapes: a stashing open, an output-path
// getcwd and a plain read.
func TestEnterHookCheckRejectsMismatches(t *testing.T) {
	out := GenerateTracepointsC(mustParseAll(t, FormatOpenat+"\n"+FormatExitOpenat+"\n"+FormatGetcwd+"\n"+FormatExitGetcwd+"\n"+FormatRead+"\n"+FormatExitRead+"\n"))
	handlers := splitGeneratedHandlers(t, out)
	for _, name := range []string{"sys_enter_openat", "sys_enter_getcwd", "sys_enter_read"} {
		if handlers[name] == "" {
			t.Fatalf("fixture lacks %s", name)
		}
		if err := checkEnterHookMatchesStash(name, handlers[name]); err != nil {
			t.Errorf("generator output: %v", err)
		}
	}
	for _, name := range []string{"sys_enter_openat", "sys_enter_getcwd"} {
		if !strings.Contains(handlers[name], "ior_on_syscall_enter_stateful(") {
			t.Errorf("%s must use the stateful enter hook", name)
		}
		mutated := strings.Replace(handlers[name], "ior_on_syscall_enter_stateful(", "ior_on_syscall_enter(", 1)
		if checkEnterHookMatchesStash(name, mutated) == nil {
			t.Errorf("%s: the plain hook on a stashing handler was not rejected", name)
		}
	}
	read := handlers["sys_enter_read"]
	if strings.Contains(read, "ior_on_syscall_enter_stateful(") {
		t.Error("sys_enter_read must use the plain enter hook")
	}
	if checkEnterHookMatchesStash("sys_enter_read", strings.Replace(read, "ior_on_syscall_enter(", "ior_on_syscall_enter_stateful(", 1)) == nil {
		t.Error("the stateful hook on a handler that stashes nothing was not rejected")
	}
}
