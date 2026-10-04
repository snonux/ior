package globalfilter

import (
	"math"
	"testing"
)

type sampleCandidate struct {
	syscall string
	family  string
	comm    string
	file    string
	pid     uint32
	tid     uint32
	fd      int32
	latency uint64
	gap     uint64
	bytes   uint64
	ret     int64
	isError bool
	// noReturn models a noreturn row (exit, exit_group, rt_sigreturn).
	noReturn bool
}

func (s sampleCandidate) SyscallValue() string { return s.syscall }
func (s sampleCandidate) FamilyValue() string  { return s.family }
func (s sampleCandidate) CommValue() string    { return s.comm }
func (s sampleCandidate) FileValue() string    { return s.file }
func (s sampleCandidate) OldFileValue() string { return "" }
func (s sampleCandidate) PIDValue() uint32     { return s.pid }
func (s sampleCandidate) TIDValue() uint32     { return s.tid }
func (s sampleCandidate) FDValue() int32       { return s.fd }
func (s sampleCandidate) LatencyValue() uint64 { return s.latency }
func (s sampleCandidate) GapValue() uint64     { return s.gap }
func (s sampleCandidate) BytesValue() uint64   { return s.bytes }
func (s sampleCandidate) ReturnValue() int64   { return s.ret }
func (s sampleCandidate) ErrorValue() bool     { return s.isError }
func (s sampleCandidate) NoReturnValue() bool  { return s.noReturn }

func testCandidate() sampleCandidate {
	return sampleCandidate{
		syscall: "read",
		family:  "FS",
		comm:    "nginx",
		file:    "/var/log/access.log",
		pid:     1234,
		tid:     1235,
		fd:      7,
		latency: 1_500_000,
		gap:     12_000,
		bytes:   4_096,
		ret:     -1,
		isError: true,
	}
}

func TestFilterZeroValueMatchesAll(t *testing.T) {
	candidate := testCandidate()
	filter := Filter{}
	if !filter.Matches(candidate) {
		t.Fatalf("zero-value filter should match all candidates")
	}
	if filter.IsActive() {
		t.Fatalf("zero-value filter should be inactive")
	}
}

func TestFilterStringAndNumericMatching(t *testing.T) {
	candidate := testCandidate()
	filter := Filter{
		Syscall:   &StringFilter{Pattern: "ea"},
		Comm:      &StringFilter{Pattern: "NGI"},
		File:      &StringFilter{Pattern: "access"},
		PID:       &NumericFilter{Op: OpEq, Value: 1234},
		TID:       &NumericFilter{Op: OpNeq, Value: 1},
		FD:        &NumericFilter{Op: OpEq, Value: 7},
		LatencyNs: &NumericFilter{Op: OpGt, Value: 1_000_000},
		GapNs:     &NumericFilter{Op: OpLte, Value: 12_000},
		Bytes:     &NumericFilter{Op: OpLt, Value: 8_192},
		RetVal:    &NumericFilter{Op: OpGte, Value: -1},
	}
	if !filter.Matches(candidate) {
		t.Fatalf("combined filter should match candidate")
	}
}

func TestFilterFamilyMatchesAndExcludes(t *testing.T) {
	candidate := testCandidate()
	candidate.family = "Polling"

	if !(&Filter{Family: &StringFilter{Pattern: "Polling"}}).Matches(candidate) {
		t.Fatalf("family filter Polling should match Polling candidate")
	}
	if !(&Filter{Family: &StringFilter{Pattern: "poll"}}).Matches(candidate) {
		t.Fatalf("family filter should match case-insensitive substring")
	}
	if (&Filter{Family: &StringFilter{Pattern: "Network"}}).Matches(candidate) {
		t.Fatalf("family filter Network should exclude Polling candidate")
	}
	if !(&Filter{Family: &StringFilter{Pattern: "Polling"}}).IsActive() {
		t.Fatalf("non-empty family filter should be active")
	}

	base := Filter{Family: &StringFilter{Pattern: "Polling"}}
	cloned := base.Clone()
	cloned.Family.Pattern = "Process"
	if base.Family.Pattern != "Polling" {
		t.Fatalf("Clone() should deep-copy the Family filter")
	}
	if base.Equal(cloned) {
		t.Fatalf("filters with different Family patterns should not be Equal")
	}
}

func TestMatchesSyscallRow(t *testing.T) {
	cases := []struct {
		name    string
		filter  Filter
		syscall string
		family  string
		want    bool
	}{
		{
			name:    "empty filter matches everything",
			filter:  Filter{},
			syscall: "epoll_wait",
			family:  "Polling",
			want:    true,
		},
		{
			name:    "matches on family",
			filter:  Filter{Family: &StringFilter{Pattern: "Polling"}},
			syscall: "epoll_wait",
			family:  "Polling",
			want:    true,
		},
		{
			name:    "excludes on non-matching family",
			filter:  Filter{Family: &StringFilter{Pattern: "FS"}},
			syscall: "epoll_wait",
			family:  "Polling",
			want:    false,
		},
		{
			name:    "matches on syscall name",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}},
			syscall: "write",
			family:  "FS",
			want:    true,
		},
		{
			name:    "excludes on non-matching syscall name",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}},
			syscall: "read",
			family:  "FS",
			want:    false,
		},
		{
			name:    "both dimensions must match",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}, Family: &StringFilter{Pattern: "FS"}},
			syscall: "write",
			family:  "FS",
			want:    true,
		},
		{
			name:    "one dimension mismatch fails the AND",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}, Family: &StringFilter{Pattern: "Polling"}},
			syscall: "write",
			family:  "FS",
			want:    false,
		},
		{
			name:    "trace-scope dimensions are ignored",
			filter:  Filter{PID: NewEqFilter(999), Comm: &StringFilter{Pattern: "nope"}},
			syscall: "write",
			family:  "FS",
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.MatchesSyscallRow(tc.syscall, tc.family); got != tc.want {
				t.Fatalf("MatchesSyscallRow(%q, %q) = %v, want %v", tc.syscall, tc.family, got, tc.want)
			}
		})
	}
}

func TestFilterStringAnchorsSupportExactPrefixAndSuffix(t *testing.T) {
	candidate := testCandidate()

	if !(&Filter{Syscall: &StringFilter{Pattern: "^read$"}}).Matches(candidate) {
		t.Fatalf("expected ^read$ to exactly match read")
	}
	if !(&Filter{Syscall: &StringFilter{Pattern: "^re"}}).Matches(candidate) {
		t.Fatalf("expected ^re to match read by prefix")
	}
	if !(&Filter{File: &StringFilter{Pattern: ".log$"}}).Matches(candidate) {
		t.Fatalf("expected .log$ to match by suffix")
	}

	candidate.syscall = "readlink"
	if (&Filter{Syscall: &StringFilter{Pattern: "^read$"}}).Matches(candidate) {
		t.Fatalf("expected ^read$ not to match readlink")
	}
	if !(&Filter{Syscall: &StringFilter{Pattern: "^read"}}).Matches(candidate) {
		t.Fatalf("expected ^read to match readlink by prefix")
	}
	if !(&Filter{Syscall: &StringFilter{Pattern: "link$"}}).Matches(candidate) {
		t.Fatalf("expected link$ to match readlink by suffix")
	}
}

// TestExactPatternMatchesOnlyTheValue checks that ExactPattern is exact for
// every value, including those the matcher would otherwise reinterpret:
// blank-padded values (the matcher trims blanks outside the anchors only),
// values with a literal edge ^ or $ (one anchor is taken per end only), and
// the empty value. Exact means case too: a value differing only in case is a
// different file or comm, so "/TMP/A" is a miss for "/tmp/a" (non-ASCII
// values included, which would otherwise take the lowering fallback).
func TestExactPatternMatchesOnlyTheValue(t *testing.T) {
	for _, tt := range []struct {
		value string
		match []string
		miss  []string
	}{
		{"/tmp/a", []string{"/tmp/a"}, []string{"/TMP/A", "/tmp/A", "/tmp/ab", "/var/tmp/a", "/tmp/a "}},
		{"/tmp/A", []string{"/tmp/A"}, []string{"/tmp/a", "/TMP/a"}},
		{"Ärger", []string{"Ärger"}, []string{"ärger", "ÄRGER"}},
		{"\u212A", []string{"\u212A"}, []string{"k", "K"}},
		{"/tmp/a ", []string{"/tmp/a "}, []string{"/tmp/a", "/tmp/ab", "/tmp/a  "}},
		{"  sh  ", []string{"  sh  "}, []string{"sh", " sh ", "bash"}},
		{"x$", []string{"x$"}, []string{"x", "ax$", "x$y"}},
		{"^x", []string{"^x"}, []string{"x", "^xy"}},
		{"^", []string{"^"}, []string{"", "^^", "a"}},
		{"$", []string{"$"}, []string{"", "$$"}},
		{"$$", []string{"$$"}, []string{"$", "$$$"}},
		{"", []string{""}, []string{"a", " "}},
	} {
		sf := &StringFilter{Pattern: ExactPattern(tt.value)}
		for _, v := range tt.match {
			if !matchString(sf, v) {
				t.Errorf("ExactPattern(%q) = %q should match %q", tt.value, sf.Pattern, v)
			}
		}
		for _, v := range tt.miss {
			if matchString(sf, v) {
				t.Errorf("ExactPattern(%q) = %q should not match %q", tt.value, sf.Pattern, v)
			}
		}
	}
}

// TestDirPatternMatchesDirectChildrenOnly checks that DirPattern selects the
// paths directly in the directory - LiteralDir(path) == dir - and nothing
// else: no file of a subdirectory (the dashboard counts those under their
// own rows), no sibling sharing the dir's name as a prefix, and for the root
// only top-level entries (task ip2; the old prefix ^dir/ selected the whole
// subtree, so the "/" row filtered nothing).
func TestDirPatternMatchesDirectChildrenOnly(t *testing.T) {
	for _, tt := range []struct {
		dir   string
		want  string
		match []string
		miss  []string
	}{
		{"/tmp", "^/tmp/*", []string{"/tmp/a", "/tmp/", "/tmp/*"}, []string{"/tmp", "/tmp/sub/b", "/tmpfoo/a", "/var/tmp/a", "/TMP/a"}},
		{"/", "^/*", []string{"/a", "/etc", "/", "//x"}, []string{"/etc/passwd", "a", "socket:[1]", "a/b", ""}},
		{"/tmp/a ", "^/tmp/a /*", []string{"/tmp/a /x"}, []string{"/tmp/a/x", "/tmp/a /x/y"}},
		{"/a$", "^/a$/*", []string{"/a$/x"}, []string{"/a/x"}},
		// The literal dir of "a//b" is "a/": it must not also select "a/x".
		{"a/", "^a//*", []string{"a//b"}, []string{"a/x", "a/b", "a//b/c"}},
		{"   ", "^   /*", []string{"   /z"}, []string{"/z", " /z"}},
		{"./src", "^./src/*", []string{"./src/main.go"}, []string{"src/main.go", "./srcx/a", "./src/x/y"}},
		// A dir that itself ends in "*" is still just text before the suffix.
		{"/a/*", "^/a/*/*", []string{"/a/*/x"}, []string{"/a/x", "/a/*"}},
	} {
		got := DirPattern(tt.dir)
		if got != tt.want {
			t.Errorf("DirPattern(%q) = %q, want %q", tt.dir, got, tt.want)
		}
		sf := &StringFilter{Pattern: got}
		for _, v := range tt.match {
			if !matchString(sf, v) {
				t.Errorf("DirPattern(%q) should match %q", tt.dir, v)
			}
		}
		for _, v := range tt.miss {
			if matchString(sf, v) {
				t.Errorf("DirPattern(%q) should not match %q", tt.dir, v)
			}
		}
	}
}

// TestDirChildrenPatternIsCaseSensitive pins the case rule of the typed
// ^dir/* form, which must equal the row filter's: case-sensitive like
// ^exact$, since both are derived from exact values. The neighbouring forms
// keep their own semantics: ^dir/*$ is the exact path "dir/*", and a prefix
// not ending in "/*" still folds case. "^//*" also names the root.
func TestDirChildrenPatternIsCaseSensitive(t *testing.T) {
	for _, tt := range []struct {
		pattern, value string
		want           bool
	}{
		{"^/tmp/A/*", "/tmp/A/x", true},
		{"^/tmp/A/*", "/tmp/a/x", false},
		{"^/tmp/a/*", "/tmp/A/x", false},
		{"^/tmp/Ä/*", "/tmp/ä/x", false},
		{"  ^/tmp/*  ", "/tmp/x", true},
		{"^//*", "/x", true},
		{"^//*", "/x/y", false},
		{"^/tmp/*$", "/tmp/*", true},
		{"^/tmp/*$", "/tmp/x", false},
		{"^/TMP/", "/tmp/sub/x", true},
		{"/tmp/*", "/tmp/x", false},
		{"/tmp/*", "/x/tmp/*", true},
	} {
		if got := matchString(&StringFilter{Pattern: tt.pattern}, tt.value); got != tt.want {
			t.Errorf("matchString(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

// TestLiteralDirMatchesDirPattern cross-checks the definition: for every
// path with a separator, the pattern built from its LiteralDir selects it,
// and a path without a separator has no dir at all.
func TestLiteralDirMatchesDirPattern(t *testing.T) {
	for _, p := range []string{"/tmp/a", "/a", "/", "//x", "a//b", "./a", "a/../b/c", "   /z", "a/"} {
		dir, ok := LiteralDir(p)
		if !ok || !matchString(&StringFilter{Pattern: DirPattern(dir)}, p) {
			t.Errorf("LiteralDir(%q) = %q, %v: its DirPattern does not select it", p, dir, ok)
		}
	}
	for _, p := range []string{"", "a.log", "socket:[1]"} {
		if dir, ok := LiteralDir(p); ok {
			t.Errorf("LiteralDir(%q) = %q, want no dir", p, dir)
		}
	}
}

// TestStringFilterCaseSensitivityByAnchorMode pins the case rule of
// matchString for typed patterns: substring, ^prefix and suffix$ ignore case,
// while the fully anchored ^exact$ - what ExactPattern produces and what a
// user types for "exactly this" - does not. Blanks outside the anchors are
// trimmed before the rule applies, and a lone anchor stays a match-all.
func TestStringFilterCaseSensitivityByAnchorMode(t *testing.T) {
	for _, tt := range []struct {
		pattern, value string
		want           bool
	}{
		{"TMP", "/tmp/a", true},
		{"^/TMP", "/tmp/a", true},
		{"/A$", "/tmp/a", true},
		{"^/tmp/a$", "/tmp/a", true},
		{"^/tmp/a$", "/tmp/A", false},
		{"^/TMP/A$", "/tmp/a", false},
		{"  ^Bash$  ", "Bash", true},
		{"  ^Bash$  ", "bash", false},
		{"^Ärger$", "ärger", false},
		{"^ärger", "ÄRGER-x", true},
		{"^", "Anything", true},
		{"$", "Anything", true},
		{"^$", "", true},
		{"^$", "A", false},
	} {
		if got := matchString(&StringFilter{Pattern: tt.pattern}, tt.value); got != tt.want {
			t.Errorf("matchString(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestFilterErrorsOnlyAndClone(t *testing.T) {
	filter := Filter{
		ErrorsOnly: true,
		File:       &StringFilter{Pattern: "access"},
		FD:         &NumericFilter{Op: OpEq, Value: 7},
	}
	clone := filter.Clone()
	clone.File.Pattern = "different"
	clone.FD.Value = 3

	if filter.File.Pattern != "access" {
		t.Fatalf("Clone() should deep-copy string filters")
	}
	if filter.FD.Value != 7 {
		t.Fatalf("Clone() should deep-copy numeric filters")
	}
	if !filter.Matches(testCandidate()) {
		t.Fatalf("errors-only filter should match error candidate")
	}

	candidate := testCandidate()
	candidate.isError = false
	if filter.Matches(candidate) {
		t.Fatalf("errors-only filter should reject non-error candidate")
	}
}

func TestFilterEqual(t *testing.T) {
	base := Filter{
		Syscall:    &StringFilter{Pattern: "read"},
		Comm:       &StringFilter{Pattern: "nginx"},
		File:       &StringFilter{Pattern: "/var/log"},
		PID:        &NumericFilter{Op: OpEq, Value: 42},
		TID:        &NumericFilter{Op: OpNeq, Value: 99},
		FD:         &NumericFilter{Op: OpEq, Value: 7},
		LatencyNs:  &NumericFilter{Op: OpGt, Value: 1_000},
		GapNs:      &NumericFilter{Op: OpGte, Value: 500},
		Bytes:      &NumericFilter{Op: OpLt, Value: 4_096},
		RetVal:     &NumericFilter{Op: OpEq, Value: -1},
		ErrorsOnly: true,
	}
	if !base.Equal(base.Clone()) {
		t.Fatalf("expected cloned filter to compare equal")
	}

	mutated := base.Clone()
	mutated.File.Pattern = "/tmp"
	if mutated.Equal(base) {
		t.Fatalf("expected differing file pattern to compare unequal")
	}

	mutated = base.Clone()
	mutated.Bytes = nil
	if mutated.Equal(base) {
		t.Fatalf("expected missing numeric filter to compare unequal")
	}
}

// TestEqValueReturnsInt64PreservesLargeValues verifies that EqValue returns
// int64 so that values larger than math.MaxInt32 are not silently truncated on
// 32-bit architectures (where int is 32 bits wide).
func TestEqValueReturnsInt64PreservesLargeValues(t *testing.T) {
	// A value that would be truncated to a different number if cast to int32.
	large := int64(math.MaxInt32) + 1
	f := &NumericFilter{Op: OpEq, Value: large}
	got, ok := f.EqValue()
	if !ok {
		t.Fatalf("EqValue() returned ok=false for a valid positive value")
	}
	if got != large {
		t.Fatalf("EqValue() = %d, want %d (int64 value must not be truncated)", got, large)
	}

	// Nil filter must return (0, false).
	var nilFilter *NumericFilter
	if v, ok := nilFilter.EqValue(); ok || v != 0 {
		t.Fatalf("EqValue() on nil filter: got (%d, %v), want (0, false)", v, ok)
	}

	// Non-OpEq filter must return (0, false).
	neqFilter := &NumericFilter{Op: OpNeq, Value: 1}
	if v, ok := neqFilter.EqValue(); ok || v != 0 {
		t.Fatalf("EqValue() on OpNeq filter: got (%d, %v), want (0, false)", v, ok)
	}

	// Non-positive value must return (0, false).
	zeroFilter := &NumericFilter{Op: OpEq, Value: 0}
	if v, ok := zeroFilter.EqValue(); ok || v != 0 {
		t.Fatalf("EqValue() on zero value: got (%d, %v), want (0, false)", v, ok)
	}
}
