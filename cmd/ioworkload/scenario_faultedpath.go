package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// faultedPathNames issues path-taking syscalls whose path strings live on
// pages the process has mapped but never touched. The tracer's sys_enter
// bpf_probe_read_user_str() is a nofault read, so it fails with -EFAULT on such
// a page and the enter event carries an empty name; only the exit-side re-read
// (the OPEN_NAME_FIXUP_EVENT recovery, internal/c/filter.c) can name the row.
// That is exactly the case a string in freshly mmap'ed library .rodata hits
// for real, which ordinary Go strings (touched when the runtime built them)
// never do - hence a dedicated scenario.
//
// Every syscall here is raw so Go's syscall wrappers cannot substitute another
// one or touch the pointer, and every expected failure is checked so a
// scenario that silently stopped exercising the syscall fails loudly.
func faultedPathNames() error {
	dir, cleanup, err := makeTempDir("faulted-path")
	if err != nil {
		return err
	}
	defer cleanup()
	pages := &faultedPages{dir: dir}
	defer pages.release()

	if err := faultedSingleNames(dir, pages); err != nil {
		return err
	}
	return faultedRenames(dir, pages)
}

// faultedSingleNames covers the pathname kind with three syscalls that fail
// with ENOENT, so the row's file is the only evidence the name was captured.
func faultedSingleNames(dir string, pages *faultedPages) error {
	at := func(name string) (uintptr, error) { return pages.untouched(filepath.Join(dir, name)) }

	missing, err := at("faulted-access-missing")
	if err != nil {
		return err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_ACCESS, missing, 0, 0); errno != syscall.ENOENT {
		return fmt.Errorf("access(faulted): errno %v, want ENOENT", errno)
	}

	missing, err = at("faulted-stat-missing")
	if err != nil {
		return err
	}
	var st syscall.Stat_t
	atFDCWD := ^uintptr(99) // AT_FDCWD = -100
	if _, _, errno := syscall.Syscall6(syscall.SYS_NEWFSTATAT, atFDCWD, missing,
		uintptr(unsafe.Pointer(&st)), 0, 0, 0); errno != syscall.ENOENT {
		return fmt.Errorf("newfstatat(faulted): errno %v, want ENOENT", errno)
	}

	missing, err = at("faulted-unlink-missing")
	if err != nil {
		return err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, atFDCWD, missing, 0); errno != syscall.ENOENT {
		return fmt.Errorf("unlinkat(faulted): errno %v, want ENOENT", errno)
	}
	return nil
}

// faultedRenames covers the name kind: rename(old, new) can fault either
// name, both or neither, and each recovery is independent, so all three
// combinations that involve a fault run (the fourth is an ordinary rename).
func faultedRenames(dir string, pages *faultedPages) error {
	for _, tc := range []struct {
		name               string
		faultOld, faultNew bool
		oldBase, newBase   string
	}{
		{"both", true, true, "faulted-both-old", "faulted-both-new"},
		{"old only", true, false, "faulted-oldonly-old", "touched-oldonly-new"},
		{"new only", false, true, "touched-newonly-old", "faulted-newonly-new"},
	} {
		oldPath, newPath := filepath.Join(dir, tc.oldBase), filepath.Join(dir, tc.newBase)
		if err := os.WriteFile(oldPath, []byte("x"), 0o644); err != nil {
			return fmt.Errorf("create %s: %w", oldPath, err)
		}
		oldPtr, err := pages.pointer(oldPath, tc.faultOld)
		if err != nil {
			return err
		}
		newPtr, err := pages.pointer(newPath, tc.faultNew)
		if err != nil {
			return err
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_RENAME, oldPtr, newPtr, 0); errno != 0 {
			return fmt.Errorf("rename(%s): %w", tc.name, errno)
		}
	}
	return nil
}

// faultedMoveMounts covers move_mount (task vs2), whose from/to pathnames are
// the two-path counterpart of rename's old/new names with their own recovery
// slots: each combination of a faulted from_pathname and/or to_pathname runs
// once. Both paths name existing plain directories, so both lookups succeed
// (the kernel copies both strings in, faulting their pages, whatever order it
// resolves them in) and the call then fails with EINVAL because the source is
// not the root of a mount. Nothing is ever moved. The kernel checks
// CAP_SYS_ADMIN before reading either path, so the scenario needs root, like
// the integration suite that runs it; anything but EINVAL fails it loudly.
func faultedMoveMounts() error {
	dir, cleanup, err := makeTempDir("faulted-move-mount")
	if err != nil {
		return err
	}
	defer cleanup()
	pages := &faultedPages{dir: dir}
	defer pages.release()

	for _, tc := range []struct {
		name               string
		faultFrom, faultTo bool
		fromBase, toBase   string
	}{
		{"both", true, true, "faulted-mm-both-from", "faulted-mm-both-to"},
		{"from only", true, false, "faulted-mm-fromonly-from", "touched-mm-fromonly-to"},
		{"to only", false, true, "touched-mm-toonly-from", "faulted-mm-toonly-to"},
	} {
		if err := faultedMoveMount(dir, pages, tc.name, tc.faultFrom, tc.faultTo, tc.fromBase, tc.toBase); err != nil {
			return err
		}
	}
	return nil
}

// faultedMoveMount creates the two directories and issues one
// move_mount(AT_FDCWD, from, AT_FDCWD, to, 0) on them.
func faultedMoveMount(dir string, pages *faultedPages, name string, faultFrom, faultTo bool, fromBase, toBase string) error {
	fromPath, toPath := filepath.Join(dir, fromBase), filepath.Join(dir, toBase)
	for _, d := range []string{fromPath, toPath} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	fromPtr, err := pages.pointer(fromPath, faultFrom)
	if err != nil {
		return err
	}
	toPtr, err := pages.pointer(toPath, faultTo)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(unix.SYS_MOVE_MOUNT, atFDCWD, fromPtr, atFDCWD, toPtr, 0, 0)
	if errno != syscall.EINVAL {
		return fmt.Errorf("move_mount(%s): errno %v, want EINVAL", name, errno)
	}
	return nil
}

// faultedPages owns the private file mappings that hold the path strings.
type faultedPages struct {
	dir      string
	mappings [][]byte
	touched  [][]byte // plain NUL-terminated copies, kept reachable for the syscall
	next     int
}

// untouched returns the address of a NUL-terminated copy of path on a freshly
// mmap'ed file page that nothing in this process has read or written. The file
// contents are in the page cache (this process just wrote them) but not in the
// process' page tables, which is what makes a nofault read of it fail.
func (p *faultedPages) untouched(path string) (uintptr, error) {
	backing := filepath.Join(p.dir, fmt.Sprintf(".backing-%d", p.next))
	p.next++
	if err := os.WriteFile(backing, append([]byte(path), 0), 0o644); err != nil {
		return 0, fmt.Errorf("write backing file: %w", err)
	}
	fd, err := syscall.Open(backing, syscall.O_RDONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("open backing file: %w", err)
	}
	defer syscall.Close(fd)
	mapping, err := syscall.Mmap(fd, 0, os.Getpagesize(), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return 0, fmt.Errorf("mmap backing file: %w", err)
	}
	p.mappings = append(p.mappings, mapping)
	return uintptr(unsafe.Pointer(&mapping[0])), nil
}

// pointer returns the address of path as either an untouched page (faulted) or
// an ordinary heap copy the process itself wrote, so the nofault read works.
func (p *faultedPages) pointer(path string, faulted bool) (uintptr, error) {
	if faulted {
		return p.untouched(path)
	}
	b, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("path bytes: %w", err)
	}
	// Keep the copy reachable until release(): the address is only a uintptr.
	p.touched = append(p.touched, unsafe.Slice(b, len(path)+1))
	return uintptr(unsafe.Pointer(b)), nil
}

func (p *faultedPages) release() {
	for _, mapping := range p.mappings {
		_ = syscall.Munmap(mapping)
	}
}
