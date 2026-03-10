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

func TestFdFileAddFlags(t *testing.T) {
	fdFile := NewFd(1, "test.txt", syscall.O_RDWR)
	fdFile.AddFlags(syscall.O_APPEND)
	expected := Flags(syscall.O_RDWR | syscall.O_APPEND)
	if fdFile.Flags() != expected {
		t.Errorf("expected O_RDWR|O_APPEND after AddFlags, got %v", fdFile.Flags())
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
