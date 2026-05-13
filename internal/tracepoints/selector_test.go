package tracepoints

import "testing"

func TestParseSelectorEmpty(t *testing.T) {
	// An empty attach and exclude string means accept everything.
	sel, err := ParseSelector("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("expected ShouldAttach=true for empty selector")
	}
}

func TestParseSelectorAttachFilter(t *testing.T) {
	// Only openat tracepoints should be accepted when an explicit attach list
	// is provided.
	sel, err := ParseSelector("^sys_enter_openat$,^sys_exit_openat$", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Error("expected ShouldAttach=true for sys_enter_openat")
	}
	if !sel.ShouldAttach("sys_exit_openat") {
		t.Error("expected ShouldAttach=true for sys_exit_openat")
	}
	if sel.ShouldAttach("sys_enter_write") {
		t.Error("expected ShouldAttach=false for sys_enter_write (not in attach list)")
	}
}

func TestParseSelectorExcludeFilter(t *testing.T) {
	// Excluded tracepoints are rejected even when no explicit attach list exists.
	sel, err := ParseSelector("", "name_to_handle_at,open_by_handle_at")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sel.ShouldAttach("sys_enter_name_to_handle_at") {
		t.Error("expected ShouldAttach=false for excluded tracepoint")
	}
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Error("expected ShouldAttach=true for non-excluded tracepoint")
	}
}

func TestParseSelectorExcludeTakesPrecedence(t *testing.T) {
	// An exclude pattern beats an attach pattern when both match.
	sel, err := ParseSelector("openat", "openat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sel.ShouldAttach("sys_enter_openat") {
		t.Error("expected ShouldAttach=false: exclude must beat attach")
	}
}

func TestParseSelectorInvalidRegexReturnsError(t *testing.T) {
	_, err := ParseSelector("[", "")
	if err == nil {
		t.Fatal("expected error for invalid attach regex")
	}
}

func TestParseSelectorInvalidExcludeRegexReturnsError(t *testing.T) {
	_, err := ParseSelector("", "[")
	if err == nil {
		t.Fatal("expected error for invalid exclude regex")
	}
}

func TestSelectorCloneIsIndependent(t *testing.T) {
	// Modifications to the clone's Attach slice must not affect the original.
	sel, err := ParseSelector("openat", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	clone := sel.Clone()
	clone.Attach = nil
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Error("original Selector was mutated through clone")
	}
}
