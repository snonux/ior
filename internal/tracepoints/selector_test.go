package tracepoints

import (
	"strings"
	"testing"
)

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

func TestSelectorCloneCopiesSyscallAllowlist(t *testing.T) {
	sel := Selector{
		Syscalls: map[string]struct{}{
			"openat": {},
		},
		RestrictSyscalls: true,
	}
	clone := sel.Clone()
	delete(clone.Syscalls, "openat")
	if !sel.ShouldAttach("sys_enter_openat") {
		t.Fatal("original syscall allowlist mutated through clone")
	}
}

// TestParseSelectorTrimsAndSkipsBlankEntries pins the -tps/-tpsExclude list
// splitting. An empty regex matches every name, so before entries were
// trimmed and filtered a trailing comma attached (or excluded) every
// tracepoint, and a space after a comma produced a pattern that never matched.
func TestParseSelectorTrimsAndSkipsBlankEntries(t *testing.T) {
	tests := []struct {
		name        string
		attach      string
		exclude     string
		wantAttach  []string
		wantReject  []string
		wantNAttach int
		wantNExcl   int
	}{
		{
			name:        "trailing comma in attach does not attach everything",
			attach:      "^sys_enter_read$,",
			wantAttach:  []string{"sys_enter_read"},
			wantReject:  []string{"sys_enter_write", "sys_enter_openat"},
			wantNAttach: 1,
		},
		{
			name:        "leading and doubled commas in attach are ignored",
			attach:      ",^sys_enter_read$,,^sys_enter_write$",
			wantAttach:  []string{"sys_enter_read", "sys_enter_write"},
			wantReject:  []string{"sys_enter_openat"},
			wantNAttach: 2,
		},
		{
			name:        "space after comma in attach still matches",
			attach:      "^sys_enter_read$, ^sys_enter_write$",
			wantAttach:  []string{"sys_enter_read", "sys_enter_write"},
			wantReject:  []string{"sys_enter_openat"},
			wantNAttach: 2,
		},
		{
			name:        "tabs and newlines around attach entries are trimmed",
			attach:      "\t^sys_enter_read$\n,\t^sys_enter_write$ ",
			wantAttach:  []string{"sys_enter_read", "sys_enter_write"},
			wantReject:  []string{"sys_enter_openat"},
			wantNAttach: 2,
		},
		{
			name:       "trailing comma in exclude does not exclude everything",
			exclude:    "^sys_enter_read$,",
			wantAttach: []string{"sys_enter_write", "sys_enter_openat"},
			wantReject: []string{"sys_enter_read"},
			wantNExcl:  1,
		},
		{
			name:       "space after comma in exclude still matches",
			exclude:    "^sys_enter_read$, ^sys_enter_write$",
			wantAttach: []string{"sys_enter_openat"},
			wantReject: []string{"sys_enter_read", "sys_enter_write"},
			wantNExcl:  2,
		},
		{
			name:       "comma-only and blank lists behave like unset",
			attach:     " , ,",
			exclude:    ",",
			wantAttach: []string{"sys_enter_read", "sys_enter_openat"},
		},
		{
			name:       "whitespace-only lists behave like unset",
			attach:     "   ",
			exclude:    "\t",
			wantAttach: []string{"sys_enter_read", "sys_enter_openat"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel, err := ParseSelector(tt.attach, tt.exclude)
			if err != nil {
				t.Fatalf("ParseSelector(%q, %q) error: %v", tt.attach, tt.exclude, err)
			}
			if got := len(sel.Attach); got != tt.wantNAttach {
				t.Errorf("len(Attach) = %d, want %d", got, tt.wantNAttach)
			}
			if got := len(sel.Exclude); got != tt.wantNExcl {
				t.Errorf("len(Exclude) = %d, want %d", got, tt.wantNExcl)
			}
			for _, name := range tt.wantAttach {
				if !sel.ShouldAttach(name) {
					t.Errorf("ShouldAttach(%q) = false, want true", name)
				}
			}
			for _, name := range tt.wantReject {
				if sel.ShouldAttach(name) {
					t.Errorf("ShouldAttach(%q) = true, want false", name)
				}
			}
		})
	}
}

// TestParseSelectorInvalidEntryAmongPaddedEntriesReturnsError ensures that
// trimming does not mask a genuinely bad pattern and that the error names the
// trimmed entry rather than the padded input.
func TestParseSelectorInvalidEntryAmongPaddedEntriesReturnsError(t *testing.T) {
	tests := []struct {
		name    string
		attach  string
		exclude string
	}{
		{name: "attach", attach: "read, [ ,write"},
		{name: "exclude", exclude: "read, [ ,write"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSelector(tt.attach, tt.exclude)
			if err == nil {
				t.Fatal("expected error for invalid regex entry")
			}
			if want := `unable to compile regex "["`; !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not contain %q", err, want)
			}
		})
	}
}
