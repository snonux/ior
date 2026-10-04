package types

import (
	"strings"
	"testing"
)

// TestNoReturnMarksExactlyTheNoreturnEnters pins the committed artifact (task
// pr2): the event loop turns an enter whose TraceId.NoReturn is true into a
// complete row instead of parking it, so the set must hold exactly the
// sys_enter IDs of exit, exit_group and rt_sigreturn. A returning syscall in
// the set would lose its exit (its enter would become a row with no return
// value and its real exit would find nothing to pair with); a noreturn
// syscall missing from it would park forever and never produce a row again.
func TestNoReturnMarksExactlyTheNoreturnEnters(t *testing.T) {
	want := map[string]bool{"exit": true, "exit_group": true, "rt_sigreturn": true}
	found := map[string]bool{}
	for id, tracepoint := range traceId2String {
		isEnter := strings.HasPrefix(tracepoint, "enter_")
		expected := isEnter && want[id.Name()]
		if id.NoReturn() != expected {
			t.Errorf("%s (id %d): NoReturn() = %v, want %v", tracepoint, id, id.NoReturn(), expected)
		}
		if id.NoReturn() {
			found[id.Name()] = true
		}
	}
	for name := range want {
		if !found[name] {
			t.Errorf("no sys_enter_%s trace ID is marked NoReturn", name)
		}
	}
	if TraceId(0).NoReturn() {
		t.Error("an unknown trace ID must not be NoReturn")
	}
}
