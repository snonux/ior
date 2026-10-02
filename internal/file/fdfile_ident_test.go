package file

import (
	"fmt"
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
	if got := (*FdFile)(nil).Ident(); got != 0 {
		t.Fatalf("nil FdFile has identity %#x, want 0", got)
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
// that is, whatever kind of file is behind it: the number fdinfo prints must
// be the inode's, which fstat reports independently.
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

func TestParseInodeFromFdInfo(t *testing.T) {
	const head = "pos:\t0\nflags:\t0100002\nmnt_id:\t29\n"
	for _, tc := range []struct {
		name, data string
		want       uint64
		wantOK     bool
	}{
		{name: "ordinary fdinfo", data: head + "ino:\t4711\n", want: 4711, wantOK: true},
		{name: "wider than 32 bits", data: head + "ino:\t4294967338\n", want: 0x10000002a, wantOK: true},
		{name: "followed by other lines", data: head + "ino:\t7\neventfd-count:\t0\n", want: 7, wantOK: true},
		{name: "kernel before the line existed", data: head},
		{name: "malformed number", data: head + "ino:\tabc\n"},
		{name: "negative number", data: head + "ino:\t-3\n"},
		// Another line that merely contains the word is not the line.
		{name: "inotify line", data: head + "inotify wd:1 ino:2a sdev:1\n"},
		{name: "empty", data: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseInodeFromFdInfo([]byte(tc.data))
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("parseInodeFromFdInfo = %d, %v; want %d, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// The identity is kept only while the link still reads as the name the
// answer carries: a number reused between the reads must not pair one file's
// name with another's identity.
func TestIdentOfAnswerNeedsTheLinkToStillReadAsTheName(t *testing.T) {
	const fdinfo = "pos:\t0\nflags:\t02\nmnt_id:\t29\nino:\t4711\n"
	f, err := os.Create(filepath.Join(t.TempDir(), "named.txt"))
	if err != nil {
		t.Fatal(err)
	}
	link := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	name, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got := identOfAnswer([]byte(fdinfo), link, name); got != 4711 {
		t.Fatalf("identity = %d although nothing changed, want 4711", got)
	}
	if got := identOfAnswer([]byte(fdinfo), link, name+".other"); got != 0 {
		t.Fatalf("identity = %d for a link that reads as another name, want 0", got)
	}
	if got := identOfAnswer([]byte("pos:\t0\nflags:\t02\n"), link, name); got != 0 {
		t.Fatalf("identity = %d from an fdinfo without the inode line, want 0", got)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := identOfAnswer([]byte(fdinfo), link, name); got != 0 {
		t.Fatalf("identity = %d for a link that can no longer be read, want 0", got)
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
