package file

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIdentOfInodeIsTheLowWord(t *testing.T) {
	for ino, want := range map[uint64]uint32{0: 0, 42: 42, 0xffffffff: 0xffffffff, 0x10000002a: 42, 0x500000000: 0} {
		if got := IdentOfInode(ino); got != want {
			t.Errorf("IdentOfInode(%#x) = %#x, want %#x", ino, got, want)
		}
	}
}

// The identity belongs to the file, so every copy of the descriptor's
// metadata keeps it: a duplicate, a fork's copy (both Dup) and the snapshot a
// row is emitted with (Detach). A fresh FdFile has none.
func TestIdentIsCopiedWithTheDescriptor(t *testing.T) {
	f := NewFd(3, "/data/file", syscall.O_RDWR)
	if f.Ident() != 0 {
		t.Fatalf("new FdFile has identity %#x, want 0 (unknown)", f.Ident())
	}
	f.SetIdent(4711)
	if dup := f.Dup(9); dup.Ident() != 4711 || dup.FD() != 9 {
		t.Fatalf("Dup: identity %#x on fd %d, want 4711 on 9", dup.Ident(), dup.FD())
	}
	if snapshot := f.Detach(); snapshot.Ident() != 4711 {
		t.Fatalf("Detach: identity %#x, want 4711", snapshot.Ident())
	}
	f.Dup(9).SetIdent(1)
	if f.Ident() != 4711 {
		t.Fatalf("setting a duplicate's identity changed the source's to %#x", f.Ident())
	}
}

// An unnamed file shows its identity when it has one, and only then; a named
// file never does, and Name stays empty so no filter sees a name.
func TestUnnamedFileRendersItsIdentity(t *testing.T) {
	unnamed := NewFd(5, "", -1)
	if got := unnamed.String(); got != "E:name%(5,O_NONE)" {
		t.Fatalf("unnamed file without identity = %q, want E:name%%(5,O_NONE)", got)
	}
	unnamed.SetIdent(4711)
	if got := unnamed.String(); got != "E:ino:4711%(5,O_NONE)" || unnamed.Name() != "" {
		t.Fatalf("unnamed file with identity = %q (Name %q), want E:ino:4711%%(5,O_NONE) and no name", got, unnamed.Name())
	}
	unnamed.SetIdent(0xffffffff)
	if got := string(unnamed.AppendString(nil, nil)); got != "E:ino:4294967295%(5,O_NONE)" {
		t.Fatalf("largest identity = %q, want it printed unsigned", got)
	}
	named := NewFd(5, "/data/file", syscall.O_RDONLY)
	named.SetIdent(4711)
	if got := named.String(); got != "/data/file%(5,O_RDONLY)" {
		t.Fatalf("named file with identity = %q, want the name alone", got)
	}
}

// statOf returns the inode number of the file behind this process's fd.
func statOf(t *testing.T, fd uintptr) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	return st.Ino
}

// NewFdWithPidIdent names a descriptor like NewFdWithPid and says which file
// that is, for the kinds of file a descriptor can be: procfs must be able to
// stat the link whatever is behind it.
func TestNewFdWithPidIdentIdentifiesTheFileBehindTheLink(t *testing.T) {
	regular, err := os.Create(filepath.Join(t.TempDir(), "regular.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regular.Close() }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if err := os.Remove(regular.Name()); err != nil { // a deleted file still has its inode
		t.Fatal(err)
	}

	for name, f := range map[string]*os.File{"deleted regular file": regular, "pipe": r} {
		t.Run(name, func(t *testing.T) {
			got := NewFdWithPidIdent(int32(f.Fd()), uint32(os.Getpid()))
			plain := NewFdWithPid(int32(f.Fd()), uint32(os.Getpid()))
			if got.Name() == "" || got.Name() != plain.Name() || got.Flags() != plain.Flags() || !got.NameFromProcFS() {
				t.Fatalf("got %v (procfs=%v), want what NewFdWithPid returns: %v", got, got.NameFromProcFS(), plain)
			}
			if want := IdentOfInode(statOf(t, f.Fd())); got.Ident() != want || want == 0 {
				t.Fatalf("identity = %#x, want the inode's %#x (non-zero)", got.Ident(), want)
			}
			if plain.Ident() != 0 {
				t.Fatalf("NewFdWithPid recorded identity %#x, want none", plain.Ident())
			}
		})
	}
}

func TestNewFdWithPidIdentOfAClosedDescriptorIsUnresolved(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	fd := int32(f.Fd())
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got := NewFdWithPidIdent(fd, uint32(os.Getpid()))
	if got.Name() != "" || got.Ident() != 0 || got.Flags() != Flags(-1) {
		t.Fatalf("closed fd %d resolved to %v with identity %#x, want no name, no identity, unknown flags", fd, got, got.Ident())
	}
}
