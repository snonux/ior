package file

import (
	"bytes"
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
