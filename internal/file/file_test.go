package file

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"

	"ior/internal/types"
)

func TestStringValue(t *testing.T) {
	var array [128]byte
	copy(array[:], "test string")

	if str := types.StringValue(array[:]); str != "test string" {
		t.Errorf("epxected 'test string' but got '%s' with bytes '%v'", str, []byte(str))
	}
}

func TestNewFdUnknownFlags(t *testing.T) {
	fdFile := NewFd(1, "test.txt", -1)
	if fdFile.Flags() != unknownFlag {
		t.Errorf("expected unknown flags, got %v", fdFile.Flags())
	}
}

func TestNewFdEmptyName(t *testing.T) {
	fdFile := NewFd(1, "", 0)
	str := fdFile.String()
	if !strings.Contains(str, "E:name") {
		t.Errorf("expected String() to contain 'E:name' for empty name, got '%s'", str)
	}
}

func TestFlagsIsUnknown(t *testing.T) {
	f := unknownFlag
	if f.Is(syscall.O_RDONLY) {
		t.Errorf("expected Is(O_RDONLY) to be false for unknownFlag")
	}
	if f.Is(syscall.O_WRONLY) {
		t.Errorf("expected Is(O_WRONLY) to be false for unknownFlag")
	}
	if f.Is(syscall.O_RDWR) {
		t.Errorf("expected Is(O_RDWR) to be false for unknownFlag")
	}
}

func TestFlagsStringUnknown(t *testing.T) {
	f := Flags(-1)
	if f.String() != "O_NONE" {
		t.Errorf("expected 'O_NONE' for unknown flags, got '%s'", f.String())
	}
}

func TestNewOldnameNewnameEmpty(t *testing.T) {
	var oldname, newname [128]byte
	f := NewOldnameNewname(oldname[:], newname[:])
	if f.Name() != "" {
		t.Errorf("expected empty Name(), got '%s'", f.Name())
	}
	if !strings.Contains(f.String(), "old:") || !strings.Contains(f.String(), "->new:") {
		t.Errorf("expected String() to contain 'old:' and '->new:', got '%s'", f.String())
	}
}

func TestNewPathnameEmpty(t *testing.T) {
	var pathname [128]byte
	f := NewPathname(pathname[:])
	if f.Name() != "" {
		t.Errorf("expected empty Name(), got '%s'", f.Name())
	}
	if !strings.Contains(f.String(), "pathname:") {
		t.Errorf("expected String() to contain 'pathname:', got '%s'", f.String())
	}
}

func TestNewAnonymousMapping(t *testing.T) {
	f := NewAnonymousMapping()

	if got := f.Name(); got != "anon" {
		t.Fatalf("Name() = %q, want anon", got)
	}
	if got := f.String(); got != "anon" {
		t.Fatalf("String() = %q, want anon", got)
	}
	if got := f.FD(); got != -1 {
		t.Fatalf("FD() = %d, want -1", got)
	}
	if got := f.Flags(); got != unknownFlag {
		t.Fatalf("Flags() = %v, want unknown", got)
	}
}

func TestNewRegisteredRing(t *testing.T) {
	f := NewRegisteredRing(0)

	if got := f.Name(); got != "io_uring:reg[0]" {
		t.Fatalf("Name() = %q, want io_uring:reg[0]", got)
	}
	if got := f.String(); got != "io_uring:reg[0]" {
		t.Fatalf("String() = %q, want io_uring:reg[0]", got)
	}
	// The index is not a descriptor, so the row must not claim one.
	if got := f.FD(); got != -1 {
		t.Fatalf("FD() = %d, want -1", got)
	}
	if got := f.Flags(); got != unknownFlag {
		t.Fatalf("Flags() = %v, want unknown", got)
	}
	if got := NewRegisteredRing(17).Name(); got != "io_uring:reg[17]" {
		t.Fatalf("Name() = %q, want io_uring:reg[17]", got)
	}
}

func TestFdFileSetFlags(t *testing.T) {
	fdFile := NewFd(1, "test.txt", 0)
	if fdFile.Flags() != Flags(0) {
		t.Errorf("expected flags 0, got %v", fdFile.Flags())
	}
	fdFile.SetFlags(syscall.O_WRONLY)
	if fdFile.Flags() != Flags(syscall.O_WRONLY) {
		t.Errorf("expected O_WRONLY after SetFlags, got %v", fdFile.Flags())
	}
}

func TestFdFileKeepsKnownCloseOnExecAcrossUnknownStatus(t *testing.T) {
	fdFile := NewFd(1, "test.txt", -1)
	fdFile.MergeFlags(syscall.O_CLOEXEC, syscall.O_CLOEXEC)
	if got := fdFile.Flags(); got != unknownFlag {
		t.Fatalf("partial flags = %v, want unknown status word", got)
	}

	fdFile.SetStatusFlags(syscall.O_RDWR | syscall.O_NONBLOCK)
	want := Flags(syscall.O_RDWR | syscall.O_NONBLOCK | syscall.O_CLOEXEC)
	if got := fdFile.Flags(); got != want {
		t.Fatalf("combined flags = %v, want %v", got, want)
	}
}

func TestFdFileKeepsUnknownStatusWhenCloseOnExecIsKnownClear(t *testing.T) {
	fdFile := NewFd(1, "test.txt", -1)
	fdFile.MergeFlags(syscall.O_CLOEXEC, 0)
	if got := fdFile.Flags(); got != unknownFlag {
		t.Fatalf("known-clear descriptor materialized unknown status as %v", got)
	}

	fdFile.SetStatusFlags(syscall.O_RDWR)
	if got := fdFile.Flags(); got != Flags(syscall.O_RDWR) {
		t.Fatalf("combined flags = %v, want O_RDWR", got)
	}
}

func TestFdFileAddFlags(t *testing.T) {
	fdFile := NewFd(1, "test.txt", syscall.O_RDWR)
	fdFile.AddFlags(syscall.O_APPEND)
	expected := Flags(syscall.O_RDWR | syscall.O_APPEND)
	if fdFile.Flags() != expected {
		t.Errorf("expected O_RDWR|O_APPEND after AddFlags, got %v", fdFile.Flags())
	}
}

// settableStatusFlags is the F_SETFL mask applyFcntlFdState passes.
const settableStatusFlags = syscall.O_APPEND | syscall.O_ASYNC | syscall.O_DIRECT |
	syscall.O_NOATIME | syscall.O_NONBLOCK

// TestFdFileMergeFlags pins the fcntl(2) F_SETFL update shape: only the bits
// selected by the mask move, everything else in the flag word survives.
func TestFdFileMergeFlags(t *testing.T) {
	tests := []struct {
		name  string
		start int32
		arg   int32
		want  Flags
	}{
		{
			// The real caller's shape: F_GETFL, OR in a bit, F_SETFL. The
			// access mode and the creation flags must come through untouched;
			// replacing the word instead of merging it left O_NONBLOCK alone
			// and reported the descriptor as O_RDONLY from here on.
			name:  "settable bit added, access mode and creation flags kept",
			start: syscall.O_RDWR | syscall.O_CREAT,
			arg:   syscall.O_RDWR | syscall.O_NONBLOCK,
			want:  Flags(syscall.O_RDWR | syscall.O_CREAT | syscall.O_NONBLOCK),
		},
		{
			// A merge is not an OR: a settable bit missing from arg must be
			// turned off, which is how F_SETFL clears O_NONBLOCK.
			name:  "settable bit absent from arg is cleared",
			start: syscall.O_RDWR | syscall.O_APPEND | syscall.O_NONBLOCK,
			arg:   syscall.O_RDWR | syscall.O_APPEND,
			want:  Flags(syscall.O_RDWR | syscall.O_APPEND),
		},
		{
			// Bits outside the mask are ignored in arg as well: F_SETFL cannot
			// turn a descriptor into an O_CREAT|O_TRUNC one.
			name:  "non-settable bits in arg are ignored",
			start: syscall.O_WRONLY,
			arg:   syscall.O_CREAT | syscall.O_TRUNC | syscall.O_NONBLOCK,
			want:  Flags(syscall.O_WRONLY | syscall.O_NONBLOCK),
		},
		{
			name:  "access mode is never taken from arg",
			start: syscall.O_RDWR,
			arg:   syscall.O_RDONLY | syscall.O_NONBLOCK,
			want:  Flags(syscall.O_RDWR | syscall.O_NONBLOCK),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fdFile := NewFd(1, "test.txt", tc.start)
			fdFile.MergeFlags(settableStatusFlags, tc.arg)
			if fdFile.Flags() != tc.want {
				t.Errorf("MergeFlags(%v, %v) on %v = %v, want %v",
					Flags(settableStatusFlags), Flags(tc.arg), Flags(tc.start),
					fdFile.Flags(), tc.want)
			}
		})
	}
}

// TestFdFileMergeFlagsKeepsUnknownUnknown pins that a descriptor whose flag
// word was never observed stays unknown: there is no base word to merge into,
// and synthesising one from the masked bits alone would claim an access mode
// (O_RDONLY, the zero value) that nothing ever reported.
func TestFdFileMergeFlagsKeepsUnknownUnknown(t *testing.T) {
	fdFile := NewFd(1, "test.txt", -1)
	if fdFile.Flags() != unknownFlag {
		t.Fatalf("expected unknown flags to start with, got %v", fdFile.Flags())
	}
	// The arg carries none of the masked bits, so a merge without the guard
	// would clear them out of the all-ones unknown word and turn O_NONE into a
	// concrete-looking flag list.
	fdFile.MergeFlags(settableStatusFlags, syscall.O_RDWR)
	if fdFile.Flags() != unknownFlag {
		t.Errorf("expected flags to stay unknown, got %v", fdFile.Flags())
	}
}

func TestFdFileDup(t *testing.T) {
	fdFile := NewFd(1, "original.txt", syscall.O_RDONLY)
	duped := fdFile.Dup(42)
	if duped.Name() != "original.txt" {
		t.Errorf("expected duped name 'original.txt', got '%s'", duped.Name())
	}
	if !strings.Contains(duped.String(), "42") {
		t.Errorf("expected duped String() to contain fd 42, got '%s'", duped.String())
	}
	if strings.Contains(duped.String(), "%(1,") {
		t.Errorf("expected duped String() to NOT contain old fd 1, got '%s'", duped.String())
	}
}

func TestParseFlagsFromFdInfo(t *testing.T) {
	t.Run("valid flags", func(t *testing.T) {
		flags, err := parseFlagsFromFdInfo([]byte("pos:\t0\nflags:\t0100002\nmnt_id:\t24\n"))
		if err != nil {
			t.Fatalf("parseFlagsFromFdInfo valid err = %v", err)
		}
		if flags != Flags(0o100002) {
			t.Fatalf("parseFlagsFromFdInfo valid flags = %v, want %v", flags, Flags(0o100002))
		}
	})

	t.Run("invalid octal", func(t *testing.T) {
		flags, err := parseFlagsFromFdInfo([]byte("flags:\tnot-octal\n"))
		if err == nil {
			t.Fatalf("parseFlagsFromFdInfo invalid octal expected error")
		}
		if flags != 0 {
			t.Fatalf("parseFlagsFromFdInfo invalid octal flags = %v, want 0", flags)
		}
	})

	t.Run("missing flags", func(t *testing.T) {
		flags, err := parseFlagsFromFdInfo([]byte("pos:\t0\nmnt_id:\t24\n"))
		if err == nil {
			t.Fatalf("parseFlagsFromFdInfo missing flags expected error")
		}
		if flags != unknownFlag {
			t.Fatalf("parseFlagsFromFdInfo missing flags = %v, want %v", flags, unknownFlag)
		}
	})

	t.Run("scanner error", func(t *testing.T) {
		flags, err := parseFlagsFromFdInfo(bytes.Repeat([]byte("x"), 128*1024))
		if err == nil {
			t.Fatalf("parseFlagsFromFdInfo scanner error expected error")
		}
		if flags != unknownFlag {
			t.Fatalf("parseFlagsFromFdInfo scanner error flags = %v, want %v", flags, unknownFlag)
		}
	})
}

// TestFdFileCloseOnExec pins the accessor exec handling relies on: the state
// is unknown until observed, follows open flags, and follows descriptor-level
// updates even while the status word stays unknown.
func TestFdFileCloseOnExec(t *testing.T) {
	check := func(name string, f *FdFile, wantSet, wantKnown bool) {
		t.Helper()
		if set, known := f.CloseOnExec(); set != wantSet || known != wantKnown {
			t.Errorf("%s: CloseOnExec() = (%v, %v), want (%v, %v)", name, set, known, wantSet, wantKnown)
		}
	}
	check("unknown flags", NewFd(1, "a", -1), false, false)
	check("open O_CLOEXEC", NewFd(1, "a", syscall.O_RDONLY|syscall.O_CLOEXEC), true, true)
	check("open without O_CLOEXEC", NewFd(1, "a", syscall.O_RDONLY), false, true)

	f := NewFd(1, "a", -1)
	f.AddFlags(syscall.O_CLOEXEC)
	check("close_range CLOEXEC on unknown", f, true, true)
	f.MergeFlags(syscall.O_CLOEXEC, 0)
	check("F_SETFD cleared", f, false, true)
	f.SetFlags(-1)
	check("reset to unknown", f, false, false)
	check("dup keeps state", NewFd(1, "a", syscall.O_CLOEXEC).Dup(2), true, true)
}

// escapeBrackets is a stand-in escaper that visibly rewrites its input, so a
// test can tell which parts of a rendered file went through it.
func escapeBrackets(s string) string { return "[" + s + "]" }

// TestAppendStringMatchesString checks every File kind: AppendString with no
// escaper is exactly String(), it appends to (never clobbers) dst, and an
// escaper reaches the traced paths but not the fixed decoration.
func TestAppendStringMatchesString(t *testing.T) {
	tests := []struct {
		name        string
		f           interface{ String() string }
		wantEscaped string
	}{
		{"fd", NewFd(5, "/tmp/a", 0), "[/tmp/a]%(5,O_RDONLY)"},
		{"fd empty name", NewFd(5, "", 1), "E:name%(5,O_WRONLY)"},
		{"pathname", NewPathname([]byte("/p")), "pathname:[/p]%(O_NONE)"},
		{"oldname/newname", NewOldnameNewname([]byte("/a"), []byte("/b")), "old:[/a] ->new:[/b]%(O_NONE)"},
		{"anonymous", NewAnonymousMapping(), "anon"},
		// Fixed decoration plus a number: nothing attacker-controlled to escape.
		{"registered ring", NewRegisteredRing(3), "io_uring:reg[3]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appender, ok := tt.f.(StringAppender)
			if !ok {
				t.Fatalf("%T does not implement StringAppender", tt.f)
			}
			if got := string(appender.AppendString([]byte("pre:"), nil)); got != "pre:"+tt.f.String() {
				t.Errorf("AppendString(nil) = %q, want %q", got, "pre:"+tt.f.String())
			}
			if got := string(appender.AppendString(nil, escapeBrackets)); got != tt.wantEscaped {
				t.Errorf("AppendString(escape) = %q, want %q", got, tt.wantEscaped)
			}
		})
	}
}

// TestFdFileAppendStringIsAllocationFree pins the -plain hot-path property:
// rendering into a reused buffer costs no allocation.
func TestFdFileAppendStringIsAllocationFree(t *testing.T) {
	f := NewFd(5, "/tmp/a", syscall.O_RDWR|syscall.O_CLOEXEC)
	buf := make([]byte, 0, 128)
	if allocs := testing.AllocsPerRun(100, func() { buf = f.AppendString(buf[:0], nil) }); allocs != 0 {
		t.Fatalf("AppendString allocates %.1f times, want 0", allocs)
	}
}

// TestNewFdWithProcNameKeepsTheGivenName: the caller's link text is used as is
// (no second readlink), while the flags still come from the live fdinfo.
func TestNewFdWithProcNameKeepsTheGivenName(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	got := NewFdWithProcName(int32(f.Fd()), uint32(os.Getpid()), "/given/name")
	if got.Name() != "/given/name" {
		t.Errorf("name = %q, want the given link text", got.Name())
	}
	if got.Flags() == Flags(-1) {
		t.Error("flags must come from the live fdinfo of the open descriptor")
	}

	unreadable := NewFdWithPid(1<<20, uint32(os.Getpid()))
	if unreadable.Name() != "" || unreadable.Flags() != Flags(-1) {
		t.Errorf("unreadable fd = (%q, %v), want an unnamed file with unknown flags", unreadable.Name(), unreadable.Flags())
	}
}

// Task nr2: the status word lives in the open file description that duplicates
// share; FD_CLOEXEC lives in the descriptor.

func TestFdFileDupSharesTheStatusWord(t *testing.T) {
	orig := NewFd(3, "a.txt", syscall.O_WRONLY|syscall.O_CREAT)
	dup := orig.Dup(4)
	third := dup.Dup(5)

	dup.MergeFlags(settableStatusFlags, syscall.O_APPEND|syscall.O_NONBLOCK)

	want := Flags(syscall.O_WRONLY | syscall.O_CREAT | syscall.O_APPEND | syscall.O_NONBLOCK)
	for name, f := range map[string]*FdFile{"original": orig, "dup": dup, "dup of dup": third} {
		if f.Flags() != want {
			t.Errorf("%s flags = %v, want %v", name, f.Flags(), want)
		}
	}

	// F_GETFL through any one of them refreshes all of them, and a dup made
	// afterwards starts from the refreshed word.
	third.SetStatusFlags(syscall.O_RDWR)
	if orig.Dup(6).Flags() != Flags(syscall.O_RDWR) || orig.Flags() != Flags(syscall.O_RDWR) {
		t.Errorf("SetStatusFlags through a dup did not reach the original: %v", orig.Flags())
	}
	if orig.Name() != "a.txt" || dup.FD() != 4 {
		t.Errorf("dup lost its own name/number: %q %d", orig.Name(), dup.FD())
	}
}

func TestFdFileDupLearnsAnUnknownStatusWordForEveryone(t *testing.T) {
	orig := NewFd(3, "", -1)
	dup := orig.Dup(4)
	dup.SetStatusFlags(syscall.O_RDWR)
	if orig.Flags() != Flags(syscall.O_RDWR) {
		t.Errorf("original flags = %v, want the word learned through the dup", orig.Flags())
	}
}

func TestFdFileCloseOnExecIsNotShared(t *testing.T) {
	orig := NewFd(3, "a.txt", syscall.O_RDWR)
	dup := orig.Dup(4)

	dup.MergeFlags(syscall.O_CLOEXEC, syscall.O_CLOEXEC)
	if set, _ := orig.CloseOnExec(); set || orig.Flags() != Flags(syscall.O_RDWR) {
		t.Errorf("original picked up the duplicate's FD_CLOEXEC: set=%v flags=%v", set, orig.Flags())
	}
	if dup.Flags() != Flags(syscall.O_RDWR|syscall.O_CLOEXEC) {
		t.Errorf("dup flags = %v, want O_RDWR|O_CLOEXEC", dup.Flags())
	}

	// A status change through the original keeps each descriptor's own bit.
	orig.MergeFlags(settableStatusFlags, syscall.O_NONBLOCK)
	if dup.Flags() != Flags(syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC) {
		t.Errorf("dup flags = %v, want the shared O_NONBLOCK and its own O_CLOEXEC", dup.Flags())
	}
	if orig.Flags() != Flags(syscall.O_RDWR|syscall.O_NONBLOCK) {
		t.Errorf("original flags = %v, want O_NONBLOCK without O_CLOEXEC", orig.Flags())
	}
	dup.AddFlags(syscall.O_CLOEXEC)
	if set, _ := orig.CloseOnExec(); set {
		t.Error("AddFlags(O_CLOEXEC) on the duplicate reached the original")
	}
}

func TestFdFileIndependentOpensShareNothing(t *testing.T) {
	a := NewFd(3, "same.txt", syscall.O_WRONLY)
	b := NewFd(4, "same.txt", syscall.O_WRONLY)
	a.MergeFlags(settableStatusFlags, syscall.O_APPEND)
	if b.Flags() != Flags(syscall.O_WRONLY) {
		t.Errorf("an independent open picked up O_APPEND: %v", b.Flags())
	}
}

func TestFdFileDetachSharesNothing(t *testing.T) {
	orig := NewFd(3, "a.txt", syscall.O_WRONLY|syscall.O_CLOEXEC)
	dup := orig.Dup(4)
	snap := dup.Detach()

	orig.MergeFlags(settableStatusFlags, syscall.O_APPEND)
	dup.MergeFlags(syscall.O_CLOEXEC, 0)

	if snap.FD() != 4 || snap.Name() != "a.txt" {
		t.Errorf("snapshot lost its identity: fd %d name %q", snap.FD(), snap.Name())
	}
	if snap.Flags() != Flags(syscall.O_WRONLY|syscall.O_CLOEXEC) {
		t.Errorf("snapshot flags = %v, want the flags at snapshot time", snap.Flags())
	}
	// And the snapshot's own changes stay its own.
	snap.MergeFlags(settableStatusFlags, syscall.O_NONBLOCK)
	if orig.Flags().Is(syscall.O_NONBLOCK) {
		t.Error("a change to the snapshot reached the live descriptor")
	}
}

func TestZeroFdFileKeepsItsHistoricalMeaning(t *testing.T) {
	var f FdFile
	if f.Flags() != Flags(syscall.O_RDONLY) {
		t.Errorf("zero FdFile flags = %v, want O_RDONLY", f.Flags())
	}
	dup := f.Dup(1)
	dup.MergeFlags(settableStatusFlags, syscall.O_NONBLOCK)
	if !f.Flags().Is(syscall.O_NONBLOCK) {
		t.Error("a zero FdFile does not share its description with its dup")
	}
}

// TestFdFileDetachAndConstructorsAllocateOnce pins the single-allocation layout
// (FdFile and its description in one object): Detach runs once per emitted row.
func TestFdFileDetachAndConstructorsAllocateOnce(t *testing.T) {
	orig := NewFd(3, "a.txt", syscall.O_RDWR)
	var sink *FdFile
	if allocs := testing.AllocsPerRun(100, func() { sink = orig.Detach() }); allocs != 1 {
		t.Errorf("Detach allocates %v times, want 1", allocs)
	}
	if allocs := testing.AllocsPerRun(100, func() { sink = orig.Dup(4) }); allocs != 1 {
		t.Errorf("Dup allocates %v times, want 1", allocs)
	}
	if allocs := testing.AllocsPerRun(100, func() { sink = NewFd(3, "a.txt", syscall.O_RDWR) }); allocs != 1 {
		t.Errorf("NewFd allocates %v times, want 1", allocs)
	}
	_ = sink
}
