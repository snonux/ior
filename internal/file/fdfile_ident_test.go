package file

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
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
			got, stable := NewFdWithPidIdent(int32(f.Fd()), uint32(os.Getpid()))
			plain := NewFdWithPid(int32(f.Fd()), uint32(os.Getpid()))
			if !stable {
				t.Fatalf("answer for an untouched descriptor reported as changed under the read")
			}
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
// name with another's identity, and such an answer is reported as not held.
// An fdinfo without the inode line is a held answer of unknown identity.
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
	check := func(what string, data, name string, wantIdent uint32, wantHeld bool) {
		t.Helper()
		if got, held := identOfAnswer([]byte(data), link, name); got != wantIdent || held != wantHeld {
			t.Fatalf("%s: identity %d, held %v; want %d, %v", what, got, held, wantIdent, wantHeld)
		}
	}
	check("nothing changed", fdinfo, name, 4711, true)
	check("link reads as another name", fdinfo, name+".other", 0, false)
	check("fdinfo without the inode line", "pos:\t0\nflags:\t02\n", name, 0, true)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	check("link can no longer be read", fdinfo, name, 0, false)
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
	got, stable := NewFdWithPidIdent(fd, uint32(os.Getpid()))
	if got.Name() != "" || got.Ident() != 0 || got.Flags() != Flags(-1) {
		t.Fatalf("closed fd %d resolved to %v with identity %#x, want no name, no identity, unknown flags", fd, got, got.Ident())
	}
	if !stable {
		t.Fatalf("a descriptor that is not open was reported as changed under the read: nothing to read again")
	}
}

// fakeProcDir builds the procfs directory of a process with one descriptor,
// 7: its link reads as name, and its fdinfo holds fdinfo unless that is
// empty, in which case there is no fdinfo file - what a reader finds when the
// descriptor was closed between its readlink and its fdinfo read.
func fakeProcDir(t *testing.T, name, fdinfo string) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"fd", "fdinfo"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(name, filepath.Join(dir, "fd", "7")); err != nil {
		t.Fatal(err)
	}
	if fdinfo != "" {
		if err := os.WriteFile(filepath.Join(dir, "fdinfo", "7"), []byte(fdinfo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// An answer is one consistent reading only when fdinfo could be read too: a
// link that was readable while its fdinfo is gone means the number was closed
// in between, and the answer must be reported so (it is not cached). A
// complete answer carries name, flags and identity and is stable.
func TestNewFdWithIdentReportsAnAnswerThatLostItsFdinfo(t *testing.T) {
	const name = "/data/file.txt"
	whole := fakeProcDir(t, name, "pos:\t0\nflags:\t0100002\nino:\t4711\n")
	got, stable := newFdWithIdentIn(whole, 7)
	if !stable || got.Name() != name || got.Ident() != 4711 || got.Flags() != Flags(0o100002) || !got.NameFromProcFS() {
		t.Fatalf("complete answer = %v (ident %d, stable %v), want %s with identity 4711, stable", got, got.Ident(), stable, name)
	}

	torn := fakeProcDir(t, name, "")
	got, stable = newFdWithIdentIn(torn, 7)
	if stable || got.Name() != name || got.Ident() != 0 || got.Flags() != Flags(-1) {
		t.Fatalf("answer without fdinfo = %v (ident %d, stable %v), want the name, no identity, unknown flags, not stable",
			got, got.Ident(), stable)
	}

	noLine := fakeProcDir(t, name, "pos:\t0\nflags:\t02\n")
	if got, stable = newFdWithIdentIn(noLine, 7); !stable || got.Ident() != 0 || got.Flags() != Flags(2) {
		t.Fatalf("fdinfo without an inode line = ident %d, flags %v, stable %v; want a stable answer of unknown identity",
			got.Ident(), got.Flags(), stable)
	}
}

// When the fd table bound a number is the binding's, not the file's: a
// duplicate is a new binding and starts without a time, the snapshot of a row
// keeps what its source had.
func TestBoundAtBelongsToTheBinding(t *testing.T) {
	f := NewFd(3, "/data/file", syscall.O_RDWR)
	if f.BoundAt() != 0 {
		t.Fatalf("new FdFile bound at %d, want 0 (unknown)", f.BoundAt())
	}
	f.SetBoundAt(1234)
	if dup := f.Dup(9); dup.BoundAt() != 0 {
		t.Fatalf("Dup: bound at %d, want 0: the duplicate is bound when the dup returns", dup.BoundAt())
	}
	if f.BoundAt() != 1234 || f.Detach().BoundAt() != 1234 {
		t.Fatalf("source bound at %d, snapshot at %d, want 1234 for both", f.BoundAt(), f.Detach().BoundAt())
	}
}

// Every emitted row allocates an FdFile (Detach), so its size is a cost of
// the hot path. The binding time took the word that the description, once a
// second field of the allocation, now shares with the flags: 48 bytes, the
// size the allocation had before the identity and the time existed.
func TestFdFileKeepsItsSize(t *testing.T) {
	if got := unsafe.Sizeof(FdFile{}); got != 48 {
		t.Fatalf("sizeof(FdFile) = %d, want 48", got)
	}
}
