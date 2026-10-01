package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestCreateTempIsUniqueAndBesideTarget(t *testing.T) {
	final := filepath.Join(t.TempDir(), "out.csv")
	a, err := CreateTemp(final)
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = a.Close() }()
	b, err := CreateTemp(final)
	if err != nil {
		t.Fatalf("second CreateTemp: %v", err)
	}
	defer func() { _ = b.Close() }()
	if a.Name() == b.Name() {
		t.Fatalf("two CreateTemp calls returned the same file %q", a.Name())
	}
	if filepath.Dir(a.Name()) != filepath.Dir(final) {
		t.Errorf("temp %q must sit beside the target %q (same filesystem)", a.Name(), final)
	}
	base := filepath.Base(a.Name())
	if !strings.HasPrefix(base, "ior-") || !strings.HasSuffix(base, ".tmp") {
		t.Errorf("temp name %q should be ior-<random>.tmp", base)
	}
}

// TestTempNameLengthIndependentOfFinal pins the NAME_MAX fix: a final name of
// 250 bytes must still be writable, which a temp name derived from the final
// name (final + suffix) could not be.
func TestTempNameLengthIndependentOfFinal(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, strings.Repeat("a", 250-len(".csv"))+".csv")
	if len(filepath.Base(final)) != 250 {
		t.Fatalf("test setup: base name is %d bytes", len(filepath.Base(final)))
	}

	published, err := WriteFile(final, ".csv", func(w io.Writer) error {
		_, err := io.WriteString(w, "long")
		return err
	})
	if err != nil {
		t.Fatalf("WriteFile with a 250-byte name: %v", err)
	}
	if published != final || readFile(t, final) != "long" {
		t.Errorf("published %q, content %q; want %q with long", published, readFile(t, published), final)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %v, want only the final file", entries)
	}
}

// TestCreateTempBareFilenameUsesCurrentDir covers a relative final without a
// directory part: the temp file must land in ".", not at some root path.
func TestCreateTempBareFilenameUsesCurrentDir(t *testing.T) {
	t.Chdir(t.TempDir())
	f, err := CreateTemp("out.csv")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = f.Close() }()
	if filepath.Dir(f.Name()) != "." {
		t.Errorf("temp %q not in the current directory", f.Name())
	}
}

func TestCreateTempMissingDirFails(t *testing.T) {
	_, err := CreateTemp(filepath.Join(t.TempDir(), "nope", "out.csv"))
	if err == nil || errors.Is(err, fs.ErrExist) {
		t.Fatalf("CreateTemp in a missing dir = %v, want a not-exist error", err)
	}
}

func TestPublishMovesTempToFreeName(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "x.tmp")
	final := filepath.Join(dir, "out.csv")
	writeFile(t, tmp, "data")

	got, err := Publish(tmp, final, ".csv")
	if err != nil || got != final {
		t.Fatalf("Publish = %q, %v; want %q", got, err, final)
	}
	if readFile(t, final) != "data" {
		t.Error("published content mismatch")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temp file should be gone after publish, stat err = %v", err)
	}
}

// TestPublishNeverReplacesExistingFile is the core regression: an existing
// file survives and the newcomer lands under a "-N" name before the extension.
func TestPublishNeverReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "host-default-2026-09-30_13:53:24.ior.zst")
	writeFile(t, final, "first")

	for i, want := range []string{"-1", "-2"} {
		tmp := filepath.Join(dir, "t"+want+".tmp")
		writeFile(t, tmp, "later")
		got, err := Publish(tmp, final, ".ior.zst")
		if err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
		wantPath := strings.TrimSuffix(final, ".ior.zst") + want + ".ior.zst"
		if got != wantPath {
			t.Errorf("Publish #%d = %q, want %q", i, got, wantPath)
		}
	}
	if readFile(t, final) != "first" {
		t.Error("original file was clobbered")
	}
}

func TestPublishSuffixWithoutMatchingExtension(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "plain")
	writeFile(t, final, "first")
	tmp := filepath.Join(dir, "t.tmp")
	writeFile(t, tmp, "second")
	got, err := Publish(tmp, final, ".csv")
	if err != nil || got != final+"-1" {
		t.Fatalf("Publish = %q, %v; want %q", got, err, final+"-1")
	}
}

// TestPublishDoesNotFollowDanglingSymlink pins that a symlink squatting on the
// predictable final name is treated as taken, never written through.
func TestPublishDoesNotFollowDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	final := filepath.Join(dir, "out.csv")
	if err := os.Symlink(victim, final); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "t.tmp")
	writeFile(t, tmp, "data")

	got, err := Publish(tmp, final, ".csv")
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got == final {
		t.Fatal("published over the symlink")
	}
	if _, err := os.Lstat(victim); !os.IsNotExist(err) {
		t.Errorf("symlink target was created: %v", err)
	}
}

func TestPublishMissingTempFails(t *testing.T) {
	dir := t.TempDir()
	_, err := Publish(filepath.Join(dir, "missing.tmp"), filepath.Join(dir, "out.csv"), ".csv")
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Publish of a missing temp = %v, want not-exist error", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.csv")); statErr == nil {
		t.Error("a failed publish must not leave a final file behind")
	}
}

// TestClaimThenRenameFallback exercises the path used on filesystems without
// RENAME_NOREPLACE: it must still refuse to replace and still move the data.
func TestClaimThenRenameFallback(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "t.tmp")
	final := filepath.Join(dir, "out.csv")
	writeFile(t, tmp, "data")

	if err := claimThenRename(tmp, final); err != nil {
		t.Fatalf("claimThenRename: %v", err)
	}
	if readFile(t, final) != "data" {
		t.Error("fallback did not move the data")
	}

	writeFile(t, tmp, "other")
	if err := claimThenRename(tmp, final); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("claimThenRename over existing = %v, want ErrExist", err)
	}
	if readFile(t, final) != "data" {
		t.Error("fallback clobbered the existing file")
	}
	if readFile(t, tmp) != "other" {
		t.Error("fallback must leave the temp file for the caller on failure")
	}
}

// TestConcurrentPublishersKeepEveryFile races many writers for one name and
// requires that all their payloads survive under distinct names.
func TestConcurrentPublishersKeepEveryFile(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "same-second.ior.zst")
	const writers = 16

	paths := make([]string, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := CreateTemp(final)
			if err != nil {
				t.Errorf("CreateTemp: %v", err)
				return
			}
			_, _ = f.WriteString(string(rune('A' + i)))
			_ = f.Close()
			paths[i], err = Publish(f.Name(), final, ".ior.zst")
			if err != nil {
				t.Errorf("Publish: %v", err)
			}
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	for i, p := range paths {
		if p == "" || seen[p] {
			t.Fatalf("writer %d published to %q (duplicate or empty)", i, p)
		}
		seen[p] = true
		if got := readFile(t, p); got != string(rune('A'+i)) {
			t.Errorf("writer %d: %s holds %q", i, p, got)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != writers {
		t.Errorf("dir has %d entries, want %d (no stray temp files)", len(entries), writers)
	}
}

func TestWriteFilePublishesAndKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "out.csv")
	put := func(content string) func(io.Writer) error {
		return func(w io.Writer) error { _, err := io.WriteString(w, content); return err }
	}

	first, err := WriteFile(final, ".csv", put("one"))
	if err != nil || first != final {
		t.Fatalf("first WriteFile = %q, %v", first, err)
	}
	second, err := WriteFile(final, ".csv", put("two"))
	if err != nil || second != filepath.Join(dir, "out-1.csv") {
		t.Fatalf("second WriteFile = %q, %v; want out-1.csv", second, err)
	}
	if readFile(t, first) != "one" || readFile(t, second) != "two" {
		t.Error("contents were mixed up or clobbered")
	}
}

func TestWriteFileWriteErrorPublishesNothing(t *testing.T) {
	dir := t.TempDir()
	boom := errors.New("boom")
	_, err := WriteFile(filepath.Join(dir, "out.csv"), ".csv", func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WriteFile error = %v, want boom", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("failed write left %v behind", entries)
	}
}

// TestWriteFileMissingDirReportsCreateError: a real (unhooked) create failure
// names the final path and the bare errno, not the temp name the
// *fs.PathError carried.
func TestWriteFileMissingDirReportsCreateError(t *testing.T) {
	final := filepath.Join(t.TempDir(), "nope", "out.csv")
	_, err := WriteFile(final, ".csv",
		func(io.Writer) error { t.Error("write callback ran without a file"); return nil })
	want := "create temp file for " + final + ": " + syscall.ENOENT.Error()
	if err == nil || err.Error() != want || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("WriteFile error = %v, want %q wrapping ENOENT", err, want)
	}
}

// swapHook replaces a package-level fault-injection seam for one test and
// restores it afterwards. Tests using it must not call t.Parallel.
func swapHook[T any](t *testing.T, hook *T, fake T) {
	t.Helper()
	orig := *hook
	*hook = fake
	t.Cleanup(func() { *hook = orig })
}

// assertCleanFailure pins what every failed write must look like: exactly the
// readable message want (final name only, bare errno; no ior-<hex>.tmp), the
// errno reachable through errors.Is, no temp file left in dir and the existing
// destination final untouched (still "old" and the only entry).
func assertCleanFailure(t *testing.T, err error, want string, errno syscall.Errno, dir, final string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if !errors.Is(err, errno) {
		t.Errorf("error %v does not wrap %v", err, errno)
	}
	if got := readFile(t, final); got != "old" {
		t.Errorf("destination holds %q, want it unchanged (%q)", got, "old")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %v, want only the untouched destination", entries)
	}
}

// writers are the two public entry points that share writeThenPublish: the
// generated-name WriteFile and the typed-name ReplaceFile.
var writers = map[string]func(final string) error{
	"WriteFile": func(final string) error {
		_, err := WriteFile(final, ".csv", func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err })
		return err
	},
	"ReplaceFile": func(final string) error {
		_, err := ReplaceFile(final, func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err })
		return err
	},
}

// TestWriteThenPublishCreateAndCloseErrors drives the create and close error
// branches of writeThenPublish through the seams, with the *fs.PathError (temp
// name included) the real calls return: a full disk when the temp file is
// created, and a delayed write error (quota on NFS) that only close reports.
// Both must report the final name with the bare errno, remove the temp file
// and leave the existing destination alone.
func TestWriteThenPublishCreateAndCloseErrors(t *testing.T) {
	for name, write := range writers {
		t.Run(name+"/create", func(t *testing.T) {
			swapHook(t, &openTempFile, func(path string, _ int, _ fs.FileMode) (*os.File, error) {
				return nil, &fs.PathError{Op: "open", Path: path, Err: syscall.ENOSPC}
			})
			dir := t.TempDir()
			final := filepath.Join(dir, "out.csv")
			writeFile(t, final, "old")
			assertCleanFailure(t, write(final),
				"create temp file for "+final+": "+syscall.ENOSPC.Error(), syscall.ENOSPC, dir, final)
		})
		t.Run(name+"/close", func(t *testing.T) {
			swapHook(t, &closeTempFile, func(f *os.File) error {
				if err := f.Close(); err != nil {
					t.Fatalf("real close: %v", err)
				}
				return &fs.PathError{Op: "close", Path: f.Name(), Err: syscall.EDQUOT}
			})
			dir := t.TempDir()
			final := filepath.Join(dir, "out.csv")
			writeFile(t, final, "old")
			assertCleanFailure(t, write(final),
				"finish writing "+final+": "+syscall.EDQUOT.Error(), syscall.EDQUOT, dir, final)
		})
	}
}

// TestReplaceFileChmodErrorNamesFinal drives inheritMode's chmod failure (a
// filesystem refusing the mode copy onto the temp file): publishReplace must
// strip the *fs.PathError naming the temp file to the errno, name final once,
// remove the temp file and leave the replaced-to-be file as it was.
func TestReplaceFileChmodErrorNamesFinal(t *testing.T) {
	swapHook(t, &chmodTempFile, func(path string, _ fs.FileMode) error {
		return &fs.PathError{Op: "chmod", Path: path, Err: syscall.EPERM}
	})
	dir := t.TempDir()
	final := filepath.Join(dir, "chosen.csv")
	writeFile(t, final, "old")
	assertCleanFailure(t, writers["ReplaceFile"](final),
		"publish "+final+": "+syscall.EPERM.Error(), syscall.EPERM, dir, final)
}

// TestPublishErrorsDoNotNameTheTempFile pins that a failure at the very end
// (here a final name past NAME_MAX, which only the rename notices because the
// temp name is short) names the final path once and the bare cause, never the
// internal ior-<hex>.tmp name nor the doubled paths of an *os.LinkError, for
// both the generated-name (WriteFile) and the typed-name (ReplaceFile) path.
// The errno stays reachable and the temp file is removed.
func TestPublishErrorsDoNotNameTheTempFile(t *testing.T) {
	write := func(io.Writer) error { return nil }
	for name, publishFn := range map[string]func(string) error{
		"WriteFile":   func(p string) error { _, err := WriteFile(p, ".csv", write); return err },
		"ReplaceFile": func(p string) error { _, err := ReplaceFile(p, write); return err },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			final := filepath.Join(dir, strings.Repeat("a", NameMax+1)+".csv")
			err := publishFn(final)
			if !errors.Is(err, syscall.ENAMETOOLONG) {
				t.Fatalf("got %v, want ENAMETOOLONG", err)
			}
			msg := err.Error()
			if strings.Contains(msg, ".tmp") || strings.Count(msg, final) != 1 {
				t.Fatalf("error must name the final path once and no temp file: %v", err)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("failed publish left %v behind", entries)
			}
		})
	}
}

func TestSuffixedKeepsExtensionLast(t *testing.T) {
	for _, tc := range []struct {
		final, ext string
		n          int
		want       string
	}{
		{"a.csv", ".csv", 0, "a.csv"},
		{"a.csv", ".csv", 3, "a-3.csv"},
		{"a.ior.zst", ".ior.zst", 1, "a-1.ior.zst"},
		{"A.PARQUET", ".parquet", 2, "A-2.PARQUET"},
		{"a.txt", ".csv", 1, "a.txt-1"},
		{".csv", ".csv", 1, ".csv-1"},
		{"noext", "", 1, "noext-1"},
	} {
		if got := suffixed(tc.final, tc.ext, tc.n); got != tc.want {
			t.Errorf("suffixed(%q, %q, %d) = %q, want %q", tc.final, tc.ext, tc.n, got, tc.want)
		}
	}
}

// errRename returns a renameFunc that always fails with err, counting calls.
func errRename(err error, calls *int) renameFunc {
	return func(string, string) error {
		*calls++
		return err
	}
}

// TestRenameNoReplaceFallbackDispatch pins which errors from the rename
// syscall select the O_EXCL placeholder fallback: exactly the "unsupported"
// family. The fallback must then really deliver the data.
func TestRenameNoReplaceFallbackDispatch(t *testing.T) {
	for _, errno := range []error{unix.EINVAL, unix.ENOSYS, unix.ENOTSUP} {
		t.Run(errno.Error(), func(t *testing.T) {
			dir := t.TempDir()
			tmp := filepath.Join(dir, "t.tmp")
			final := filepath.Join(dir, "out.csv")
			writeFile(t, tmp, "data")

			var calls int
			if err := renameNoReplace(errRename(errno, &calls), tmp, final); err != nil {
				t.Fatalf("renameNoReplace: %v", err)
			}
			if calls != 1 {
				t.Errorf("rename called %d times, want 1", calls)
			}
			if readFile(t, final) != "data" {
				t.Error("fallback did not deliver the data")
			}
			if _, err := os.Stat(tmp); !os.IsNotExist(err) {
				t.Errorf("temp should be gone after the fallback rename: %v", err)
			}
		})
	}
}

// TestRenameNoReplaceFallbackRefusesExisting checks the fallback keeps the
// no-replace promise on a filesystem without RENAME_NOREPLACE.
func TestRenameNoReplaceFallbackRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "t.tmp")
	final := filepath.Join(dir, "out.csv")
	writeFile(t, tmp, "new")
	writeFile(t, final, "old")

	var calls int
	err := renameNoReplace(errRename(unix.ENOTSUP, &calls), tmp, final)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("renameNoReplace = %v, want ErrExist", err)
	}
	if readFile(t, final) != "old" {
		t.Error("existing file was replaced")
	}
}

// TestRenameNoReplaceNoFallbackOnOtherErrors is the negative case: EPERM (and
// friends) are real failures. They must be returned as-is, must not trigger
// the placeholder fallback (no file appears at the destination), and EEXIST
// must map to ErrExist without a fallback either.
func TestRenameNoReplaceNoFallbackOnOtherErrors(t *testing.T) {
	for _, errno := range []error{unix.EPERM, unix.EACCES, unix.EXDEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			dir := t.TempDir()
			tmp := filepath.Join(dir, "t.tmp")
			final := filepath.Join(dir, "out.csv")
			writeFile(t, tmp, "data")

			var calls int
			err := renameNoReplace(errRename(errno, &calls), tmp, final)
			if !errors.Is(err, errno) || errors.Is(err, fs.ErrExist) {
				t.Fatalf("renameNoReplace = %v, want %v unchanged", err, errno)
			}
			if _, statErr := os.Lstat(final); !os.IsNotExist(statErr) {
				t.Errorf("fallback ran: destination exists (%v)", statErr)
			}
			if readFile(t, tmp) != "data" {
				t.Error("temp must be left for the caller")
			}
		})
	}

	dir := t.TempDir()
	tmp := filepath.Join(dir, "t.tmp")
	final := filepath.Join(dir, "out.csv")
	writeFile(t, tmp, "data")
	var calls int
	if err := renameNoReplace(errRename(unix.EEXIST, &calls), tmp, final); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("EEXIST = %v, want ErrExist", err)
	}
	if _, statErr := os.Lstat(final); !os.IsNotExist(statErr) {
		t.Errorf("EEXIST must not create the destination: %v", statErr)
	}
}

// TestWriteFileRemovesTempOnRenameError drives the whole exporter pattern
// with an EPERM rename: the error surfaces, nothing is published and the temp
// file is cleaned up (no orphan for a failure we can see).
func TestWriteFileRemovesTempOnRenameError(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "out.csv")
	var calls int
	_, err := writeThenPublish(final,
		func(w io.Writer) error { _, err := io.WriteString(w, "x"); return err },
		func(tmp string) (string, error) {
			return publish(tmp, final, ".csv", errRename(unix.EPERM, &calls))
		})
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("error = %v, want EPERM", err)
	}
	if calls != 1 {
		t.Errorf("rename called %d times, want 1 (no retry with other names)", calls)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("failed publish left %v behind", entries)
	}
}

// TestReplaceFileOverwritesExisting pins the explicit-name
// policy: the existing file is atomically replaced and the path is unchanged.
func TestReplaceFileOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "chosen.parquet")
	writeFile(t, final, "old")

	got, err := ReplaceFile(final, func(w io.Writer) error {
		_, err := io.WriteString(w, "new")
		return err
	})
	if err != nil || got != final {
		t.Fatalf("ReplaceFile = %q, %v; want %q", got, err, final)
	}
	if readFile(t, final) != "new" {
		t.Error("existing file was not replaced")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %v, want only the final file", entries)
	}
}

func TestReplaceFileWriteErrorKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "chosen.csv")
	writeFile(t, final, "old")
	boom := errors.New("boom")
	if _, err := ReplaceFile(final, func(io.Writer) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want boom", err)
	}
	if readFile(t, final) != "old" {
		t.Error("failed replace damaged the existing file")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %v, want only the old file", entries)
	}
}

// TestReplaceFileReplacesSymlinkNotTarget: a symlink at the final name is
// itself replaced by the rename; the file it pointed at is never written.
func TestReplaceFileReplacesSymlinkNotTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "precious")
	final := filepath.Join(dir, "out.csv")
	if err := os.Symlink(victim, final); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplaceFile(final, func(w io.Writer) error {
		_, err := io.WriteString(w, "new")
		return err
	}); err != nil {
		t.Fatalf("ReplaceFile: %v", err)
	}
	if readFile(t, victim) != "precious" {
		t.Error("symlink target was written through")
	}
	if readFile(t, final) != "new" {
		t.Error("final does not hold the new content")
	}
}

// withUmask sets the process umask for one test and restores it afterwards.
// The atomicfile tests do not run in parallel, so the process-wide change is
// not observable by another test.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

func modeOf(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}

func replaceWith(t *testing.T, final, content string) {
	t.Helper()
	if _, err := ReplaceFile(final, func(w io.Writer) error {
		_, err := io.WriteString(w, content)
		return err
	}); err != nil {
		t.Fatalf("ReplaceFile(%q): %v", final, err)
	}
}

// TestReplaceFilePreservesExistingMode pins that replacing a file keeps its
// permission bits (the old truncate-in-place write did): a 0600 file must not
// become world-readable 0644, and a 0755 file must not lose its exec bits.
func TestReplaceFilePreservesExistingMode(t *testing.T) {
	withUmask(t, 0o022)
	for _, mode := range []fs.FileMode{0o600, 0o640, 0o755} {
		final := filepath.Join(t.TempDir(), "chosen.csv")
		writeFile(t, final, "old")
		if err := os.Chmod(final, mode); err != nil {
			t.Fatal(err)
		}
		replaceWith(t, final, "new")
		if got := modeOf(t, final); got != mode {
			t.Errorf("mode after replace = %v, want %v", got, mode)
		}
		if readFile(t, final) != "new" {
			t.Errorf("mode %v: content not replaced", mode)
		}
	}
}

// TestReplaceFileKeepsOwner checks the best-effort chown path: replacing our
// own file leaves the owner and group as they were (chown to oneself always
// succeeds, so this runs unprivileged), and the call never fails because a
// chown was refused.
func TestReplaceFileKeepsOwner(t *testing.T) {
	final := filepath.Join(t.TempDir(), "chosen.csv")
	writeFile(t, final, "old")
	before, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	replaceWith(t, final, "new")
	after, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	b, a := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if a.Uid != b.Uid || a.Gid != b.Gid {
		t.Errorf("owner after replace = %d:%d, want %d:%d", a.Uid, a.Gid, b.Uid, b.Gid)
	}
}

// TestReplaceFileWithoutExistingUsesDefaultMode is the negative case: with
// nothing to inherit from, the new file gets 0666 filtered by the umask.
func TestReplaceFileWithoutExistingUsesDefaultMode(t *testing.T) {
	withUmask(t, 0o027)
	final := filepath.Join(t.TempDir(), "fresh.csv")
	replaceWith(t, final, "new")
	if got, want := modeOf(t, final), fs.FileMode(0o640); got != want {
		t.Errorf("mode of a fresh file = %v, want %v (0666 &^ umask)", got, want)
	}
}

// TestReplaceFileSymlinkDoesNotDonateMode: a symlink at the name is replaced
// by a regular file with the default mode; the target's mode is neither
// inherited nor changed.
func TestReplaceFileSymlinkDoesNotDonateMode(t *testing.T) {
	withUmask(t, 0o022)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "precious")
	if err := os.Chmod(victim, 0o600); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "out.csv")
	if err := os.Symlink(victim, final); err != nil {
		t.Fatal(err)
	}
	replaceWith(t, final, "new")

	if got := modeOf(t, final); got != 0o644 {
		t.Errorf("replacement mode = %v (regular file, no inheritance from the link target), want -rw-r--r--", got)
	}
	if got := modeOf(t, victim); got != 0o600 {
		t.Errorf("symlink target mode changed to %v", got)
	}
}

// TestSuffixedTruncatesStemToNameMax: a "-N" suffix must never push the file
// name past NAME_MAX; the stem gives way, on a rune boundary, and the
// extension stays last.
func TestSuffixedTruncatesStemToNameMax(t *testing.T) {
	for _, tc := range []struct {
		name string
		stem string
		ext  string
		n    int
	}{
		{"254-byte csv", strings.Repeat("a", 250), ".csv", 1},
		{"255-byte csv", strings.Repeat("a", 251), ".csv", 12},
		{"no extension", strings.Repeat("a", 255), "", 3},
		// "é" is two bytes: cutting at byte 246 would land inside one.
		{"multi-byte stem", strings.Repeat("é", 125), ".csv", 1},
	} {
		got := suffixed(tc.stem+tc.ext, tc.ext, tc.n)
		if len(got) > nameMax {
			t.Errorf("%s: suffixed name is %d bytes, want <= %d", tc.name, len(got), nameMax)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: suffixed name is not valid UTF-8", tc.name)
		}
		if want := fmt.Sprintf("-%d%s", tc.n, tc.ext); !strings.HasSuffix(got, want) {
			t.Errorf("%s: suffixed name ends %q, want suffix %q", tc.name, got[len(got)-len(want):], want)
		}
	}
	// A directory part is not counted against the limit and is kept.
	if got := suffixed("/d/"+strings.Repeat("a", 251)+".csv", ".csv", 1); !strings.HasPrefix(got, "/d/a") || len(filepath.Base(got)) != nameMax {
		t.Errorf("directory handling: got %q (base %d bytes)", got[:8], len(filepath.Base(got)))
	}
}

// TestPublishNearNameMaxCollisionKeepsBothFiles is the data-loss regression:
// publishing over an existing 254-byte name used to fail with ENAMETOOLONG on
// the "-1" candidate and delete the temp file, losing the recording.
func TestPublishNearNameMaxCollisionKeepsBothFiles(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, strings.Repeat("a", 250)+".csv")
	write := func(content string) (string, error) {
		return WriteFile(final, ".csv", func(w io.Writer) error {
			_, err := io.WriteString(w, content)
			return err
		})
	}
	first, err := write("first")
	if err != nil || first != final {
		t.Fatalf("first write = %q, %v", first, err)
	}
	second, err := write("second")
	if err != nil {
		t.Fatalf("colliding write of a 254-byte name failed: %v", err)
	}
	if second == final || len(filepath.Base(second)) > nameMax {
		t.Fatalf("second published as %q (%d bytes)", second, len(filepath.Base(second)))
	}
	if readFile(t, first) != "first" || readFile(t, second) != "second" {
		t.Error("a recording was lost or clobbered")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("dir holds %d entries, want exactly the two recordings", len(entries))
	}
}

// TestIsGeneratedName pins the name policy. Every rejected case is also
// checked against time.Parse directly, so the test proves the rejection comes
// from the parser (the real mechanism) and not from some other accident.
func TestIsGeneratedName(t *testing.T) {
	const layout = "ior-stream-20060102-150405.csv"
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"ior-stream-20260930-135324.csv", true},
		{"/some/dir/ior-stream-20260930-000000.csv", true},
		{"  ior-stream-20260930-135324.csv ", true},
		{"ior-stream-20260930-90500.csv", false},      // one-digit hour: read as hour 90
		{"ior-stream-20260930-135324", false},         // extension missing
		{"other-stream-20260930-135324.csv", false},   // wrong prefix
		{"ior-stream-20260930-135324.csv.bak", false}, // trailing junk
		{"ior-stream-20260930-135324-1.csv", false},   // collision-suffixed name
		{"ior-stream-20260931-135324.csv", false},     // no such date
		{"mine.csv", false},
		{"", false},
	} {
		if got := IsGeneratedName(tc.name, layout); got != tc.want {
			t.Errorf("IsGeneratedName(%q) = %v, want %v", tc.name, got, tc.want)
		}
		_, err := time.Parse(layout, filepath.Base(strings.TrimSpace(tc.name)))
		if (err == nil) != tc.want {
			t.Errorf("time.Parse(%q) error = %v; the case does not exercise the parser as expected", tc.name, err)
		}
	}
}

// chownCall is one recorded invocation of an injected chownFunc.
type chownCall struct {
	name     string
	uid, gid int
}

// chownRecorder returns a chownFunc that appends its calls to calls and
// returns err.
func chownRecorder(calls *[]chownCall, err error) chownFunc {
	return func(name string, uid, gid int) error {
		*calls = append(*calls, chownCall{name, uid, gid})
		return err
	}
}

// publishReplaceWith writes a temp file next to final and publishes it with
// the given chown function.
func publishReplaceWith(t *testing.T, final string, chown chownFunc) error {
	t.Helper()
	tmp, err := CreateTemp(final)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tmp, "new"); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	return publishReplace(tmp.Name(), final, chown)
}

// TestPublishReplaceChownsToExistingOwner pins that the replacement is handed
// to the uid/gid of the file it replaces. An unprivileged test cannot observe
// a real change of owner, so the chown function is injected and its arguments
// checked against the existing file's owner.
func TestPublishReplaceChownsToExistingOwner(t *testing.T) {
	final := filepath.Join(t.TempDir(), "chosen.csv")
	writeFile(t, final, "old")
	info, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)

	var calls []chownCall
	if err := publishReplaceWith(t, final, chownRecorder(&calls, nil)); err != nil {
		t.Fatalf("publishReplace: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("chown called %d times, want once: %+v", len(calls), calls)
	}
	if c := calls[0]; c.uid != int(st.Uid) || c.gid != int(st.Gid) || filepath.Dir(c.name) != filepath.Dir(final) || c.name == final {
		t.Errorf("chown(%q, %d, %d), want the temp file next to %q with owner %d:%d", c.name, c.uid, c.gid, final, st.Uid, st.Gid)
	}
	if readFile(t, final) != "new" {
		t.Error("content not replaced")
	}
}

// TestPublishReplaceIgnoresChownEPERM is the negative case: an unprivileged
// writer replacing another user's file gets EPERM from chown, which must not
// fail the publish or lose the recording, and the mode is still inherited.
func TestPublishReplaceIgnoresChownEPERM(t *testing.T) {
	final := filepath.Join(t.TempDir(), "chosen.csv")
	writeFile(t, final, "old")
	if err := os.Chmod(final, 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []chownCall
	if err := publishReplaceWith(t, final, chownRecorder(&calls, unix.EPERM)); err != nil {
		t.Fatalf("publishReplace failed on chown EPERM: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("chown called %d times, want once", len(calls))
	}
	if readFile(t, final) != "new" {
		t.Error("content not replaced after chown EPERM")
	}
	if got := modeOf(t, final); got != 0o600 {
		t.Errorf("mode after chown EPERM = %v, want 0600 (mode inheritance must not depend on chown)", got)
	}
}

// TestPublishReplaceSkipsChownWithoutRegularFile: nothing at final, or a
// symlink at final, means there is no owner to inherit, so chown is not
// called (a symlink must not donate its target's owner either).
func TestPublishReplaceSkipsChownWithoutRegularFile(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "precious")
	link := filepath.Join(dir, "link.csv")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	for name, final := range map[string]string{
		"nothing there": filepath.Join(dir, "fresh.csv"),
		"symlink":       link,
	} {
		var calls []chownCall
		if err := publishReplaceWith(t, final, chownRecorder(&calls, nil)); err != nil {
			t.Fatalf("%s: publishReplace: %v", name, err)
		}
		if len(calls) != 0 {
			t.Errorf("%s: chown called: %+v", name, calls)
		}
		if readFile(t, final) != "new" {
			t.Errorf("%s: content not published", name)
		}
	}
	if readFile(t, victim) != "precious" {
		t.Error("symlink target was modified")
	}
}

func TestProbeLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	if err := Probe(filepath.Join(dir, "out.parquet")); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Probe left %v behind", entries)
	}
}

func TestProbeBareFilenameProbesWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := Probe("out.csv"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// A vanished working directory is reported, naming it as such.
	gone := t.TempDir()
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	err := Probe("out.csv")
	if err == nil || !strings.Contains(err.Error(), "the working directory") {
		t.Fatalf("Probe in a removed directory = %v, want an error naming the working directory", err)
	}
}

func TestProbeMissingDirFails(t *testing.T) {
	err := Probe(filepath.Join(t.TempDir(), "nope", "out.parquet"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Probe = %v, want ErrNotExist", err)
	}
}

func TestProbeReadOnlyDirFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := Probe(filepath.Join(dir, "out.csv")); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Probe = %v, want ErrPermission", err)
	}
}

func TestProbeReplaceRejectsRealDirectoriesOnly(t *testing.T) {
	dir := t.TempDir()
	if err := ProbeReplace(dir); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("ProbeReplace(dir) = %v, want a directory error", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	// rename(2) of a file over a symlink replaces the link itself, so a
	// symlink to a directory is a valid target (it worked before the probe).
	if err := ProbeReplace(link); err != nil {
		t.Errorf("ProbeReplace(symlink to dir) = %v, want nil (the link is replaced)", err)
	}
	existing := filepath.Join(dir, "old.parquet")
	writeFile(t, existing, "x")
	if err := ProbeReplace(existing); err != nil {
		t.Errorf("ProbeReplace(existing file) = %v, want nil (it is replaced)", err)
	}
	if err := ProbeReplace(filepath.Join(dir, "new.parquet")); err != nil {
		t.Errorf("ProbeReplace(new file) = %v, want nil", err)
	}
	if got := readFile(t, existing); got != "x" {
		t.Errorf("ProbeReplace changed the existing file: %q", got)
	}
}

func TestProbeNameChars(t *testing.T) {
	dir := t.TempDir()
	if err := ProbeNameChars(filepath.Join(dir, "final.ior.zst"), ":"); err != nil {
		t.Fatalf("ProbeNameChars on a ':'-accepting filesystem = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("ProbeNameChars left %v behind", entries)
	}
	// A bare file name probes the working directory (it once probed a
	// directory literally called "the working directory").
	t.Chdir(dir)
	if err := ProbeNameChars("final.ior.zst", ":"); err != nil {
		t.Fatalf("ProbeNameChars with a bare name = %v", err)
	}
	if err := ProbeNameChars(filepath.Join(dir, "no-such", "final"), ":"); err == nil {
		t.Error("ProbeNameChars in a missing directory succeeded")
	}
}

// TestProbeNameCharsRejectedNameIsEINVAL uses a real failing case that needs
// no vfat mount: a NUL byte makes os.OpenFile fail with EINVAL before any
// syscall, which is what a filesystem refusing a character reports.
func TestProbeNameCharsRejectedNameIsEINVAL(t *testing.T) {
	dir := t.TempDir()
	err := ProbeNameChars(filepath.Join(dir, "final.ior.zst"), "\x00")
	if err == nil {
		t.Fatal("ProbeNameChars with a NUL byte succeeded")
	}
	if !IsNameRejected(err) || !errors.Is(err, syscall.EINVAL) {
		t.Errorf("err = %v, want it to wrap EINVAL and count as a rejected name", err)
	}
	if !strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), tempPrefix) {
		t.Errorf("err = %q, want the directory named and no internal temp name", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("failed probe left %v behind", entries)
	}
}

// TestProbeNameCharsTransientErrorIsNotARejection pins that a failure which
// is not a naming rule (here ENOENT for a missing directory; ENOSPC/EIO/EMFILE
// look the same to the caller) is returned as such and never mistaken for a
// filesystem that refuses the characters.
func TestProbeNameCharsTransientErrorIsNotARejection(t *testing.T) {
	err := ProbeNameChars(filepath.Join(t.TempDir(), "no-such", "final"), ":")
	if err == nil {
		t.Fatal("ProbeNameChars in a missing directory succeeded")
	}
	if IsNameRejected(err) {
		t.Errorf("IsNameRejected(%v) = true for a missing directory", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want it to wrap ErrNotExist", err)
	}
}

func TestIsNameRejected(t *testing.T) {
	for _, err := range []error{syscall.EINVAL, syscall.EILSEQ, &fs.PathError{Op: "open", Path: "x", Err: syscall.EINVAL}} {
		if !IsNameRejected(err) {
			t.Errorf("IsNameRejected(%v) = false, want true", err)
		}
	}
	for _, err := range []error{nil, syscall.ENOSPC, syscall.EIO, syscall.EMFILE, syscall.EDQUOT, fs.ErrNotExist} {
		if IsNameRejected(err) {
			t.Errorf("IsNameRejected(%v) = true, want false", err)
		}
	}
}

func TestRiskyNameChars(t *testing.T) {
	cases := map[string]string{
		"":                      "",
		"host-run-2026.ior.zst": "",
		"a:b:c":                 ":",
		"x?y*z\"q\"":            "?*\"",
		"a<b>c|d\\e":            "<>|\\",
		"tab\there\n":           "\t\n",
	}
	for name, want := range cases {
		if got := RiskyNameChars(name); got != want {
			t.Errorf("RiskyNameChars(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestProbeErrorNamesDirectoryNotTempFile checks the message shape: the
// absolute directory and the bare errno text, no internal ior-<hex>.tmp name.
func TestProbeErrorNamesDirectoryNotTempFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	err := Probe(filepath.Join(dir, "out.parquet"))
	if err == nil {
		t.Fatal("Probe in a missing directory succeeded")
	}
	msg := err.Error()
	if !strings.Contains(msg, dir) || !strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, tempPrefix) || strings.Contains(msg, "open ") {
		t.Errorf("Probe error = %q, want the directory and bare errno without the temp name", msg)
	}
	// A bare name reports the absolute working directory.
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := os.Chmod(cwd, 0o555); err == nil && os.Geteuid() != 0 {
		t.Cleanup(func() { _ = os.Chmod(cwd, 0o755) })
		if err := Probe("out.csv"); err == nil || !strings.Contains(err.Error(), cwd) {
			t.Errorf("Probe(bare name) = %v, want the absolute working directory %s", err, cwd)
		}
	}
}

// TestProbeReplaceProbesSpecialCharsOfTheName covers ProbeReplace's name
// character check on a normal filesystem: names with characters vfat would
// refuse pass here and leave nothing behind.
func TestProbeReplaceProbesSpecialCharsOfTheName(t *testing.T) {
	dir := t.TempDir()
	if err := ProbeReplace(filepath.Join(dir, `we:ird?*"<>|.parquet`)); err != nil {
		t.Fatalf("ProbeReplace: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("ProbeReplace left %v behind", entries)
	}
}

// TestProbeReplaceProbesNameCharsAgainstARealRejection pins the name-character
// block of ProbeReplace, which the other tests cannot: ext4/tmpfs accept
// every printable character, so only a byte the kernel interface itself
// refuses proves the probe ran. A NUL passes Probe (its temp name is
// unrelated to final) and fails only ProbeNameChars with EINVAL; without the
// block ProbeReplace would return nil here.
func TestProbeReplaceProbesNameCharsAgainstARealRejection(t *testing.T) {
	dir := t.TempDir()
	err := ProbeReplace(filepath.Join(dir, "a\x00b.parquet"))
	if err == nil {
		t.Fatal("ProbeReplace of a name with a NUL succeeded; the name-character probe did not run")
	}
	if !errors.Is(err, syscall.EINVAL) || !IsNameRejected(err) {
		t.Errorf("ProbeReplace = %v, want it to wrap EINVAL", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("ProbeReplace left %v behind", entries)
	}
}

// TestProbeReplaceAcceptsNonASCIIAndInvalidUTF8 pins that the wider probe does
// not turn names Linux accepts (any byte but NUL and '/') into startup
// failures on an ordinary filesystem.
func TestProbeReplaceAcceptsNonASCIIAndInvalidUTF8(t *testing.T) {
	dir := t.TempDir()
	for _, base := range []string{"\u00fcber-\u65e5\u672c.parquet", "bad\xff\xfe.parquet", "half\xc3.parquet", "mix\u00e9\xc3\xa9\x80.parquet"} {
		if err := ProbeReplace(filepath.Join(dir, base)); err != nil {
			t.Errorf("ProbeReplace(%q) = %v, want nil", base, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("ProbeReplace left %v behind", entries)
	}
}

// TestRiskyNameCharsNonASCII covers the non-ASCII part: runes and invalid
// bytes are returned once each, after the ASCII characters, and a lone invalid
// byte is not confused with the valid rune that starts with it.
func TestRiskyNameCharsNonASCII(t *testing.T) {
	cases := []struct{ name, want string }{
		{"unicode-\u00fc-\u65e5", "\u00fc\u65e5"},
		{"\u00fc\u00fc\u00fc", "\u00fc"},
		{"a\xffb\xffc", "\xff"},
		// U+00E9 is C3 A9; a lone C3 and a lone A9 are three different units.
		{"\u00e9\xc3x\xa9", "\u00e9\xc3\xa9"},
		// ASCII risky characters first, whatever the order in the name.
		{"\u00fc:x?", ":?\u00fc"},
		// U+FFFD written out is a valid rune, not an invalid byte.
		{"\ufffd", "\ufffd"},
	}
	for _, c := range cases {
		if got := RiskyNameChars(c.name); got != c.want {
			t.Errorf("RiskyNameChars(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestRiskyNameCharsIsBounded: a name of many distinct runes must not make the
// probe file name exceed NAME_MAX, and the ASCII characters survive the cap.
func TestRiskyNameCharsIsBounded(t *testing.T) {
	var b strings.Builder
	for r := rune(0x4e00); r < 0x4e00+200; r++ {
		b.WriteRune(r)
	}
	b.WriteString(":")
	got := RiskyNameChars(b.String())
	if !strings.HasPrefix(got, ":") {
		t.Errorf("RiskyNameChars lost the ':' behind many runes: %q", got)
	}
	if len(got) > 1+maxNonASCIIProbeBytes {
		t.Errorf("RiskyNameChars returned %d bytes, want at most %d", len(got), 1+maxNonASCIIProbeBytes)
	}
	if err := ProbeNameChars(filepath.Join(t.TempDir(), "final"), got); err != nil {
		t.Errorf("ProbeNameChars with the capped set = %v (probe name too long?)", err)
	}
}

// CreateTemp promises that the temp file is created with O_EXCL|O_NOFOLLOW, so
// a symlink planted at the guessed name is refused instead of followed (task
// 303). Dropping both flags used to pass the whole package. Two tests: the
// flags themselves, and the behaviour through a forced first name that is a
// planted symlink.
func TestCreateTempOpensWithExclusiveNoFollowFlags(t *testing.T) {
	var gotFlags int
	var gotMode fs.FileMode
	swapHook(t, &openTempFile, func(path string, flag int, mode fs.FileMode) (*os.File, error) {
		gotFlags, gotMode = flag, mode
		return os.OpenFile(path, flag, mode)
	})
	f, err := CreateTemp(filepath.Join(t.TempDir(), "out.csv"))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	for name, bit := range map[string]int{"O_EXCL": os.O_EXCL, "O_NOFOLLOW": syscall.O_NOFOLLOW, "O_CREATE": os.O_CREATE} {
		if gotFlags&bit == 0 {
			t.Errorf("CreateTemp opens without %s (flags %#x)", name, gotFlags)
		}
	}
	if gotMode != 0o666 {
		t.Errorf("mode = %#o, want 0666 (the umask filters it)", gotMode)
	}
}

func TestCreateTempRefusesASymlinkPlantedAtTheTempName(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "planted.tmp")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatal(err)
	}
	var tried []string
	swapHook(t, &openTempFile, func(path string, flag int, mode fs.FileMode) (*os.File, error) {
		tried = append(tried, path)
		if len(tried) == 1 {
			path = planted // the attacker guessed the first name
		}
		return os.OpenFile(path, flag, mode)
	})
	f, err := CreateTemp(filepath.Join(dir, "out.csv"))
	if err != nil {
		t.Fatalf("CreateTemp = %v, want it to retry past the planted name", err)
	}
	defer f.Close()
	if len(tried) != 2 {
		t.Fatalf("CreateTemp tried %d names, want the planted one refused and a retry", len(tried))
	}
	if f.Name() == planted || f.Name() == victim {
		t.Fatalf("CreateTemp returned %q, the planted link or its target", f.Name())
	}
	if _, err := f.WriteString("new"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "keep" {
		t.Fatalf("the symlink's target was written through: %q, %v", got, err)
	}
}
