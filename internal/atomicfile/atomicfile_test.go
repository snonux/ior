package atomicfile

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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

func TestWriteFileMissingDirReportsCreateError(t *testing.T) {
	_, err := WriteFile(filepath.Join(t.TempDir(), "nope", "out.csv"), ".csv",
		func(io.Writer) error { t.Error("write callback ran without a file"); return nil })
	if err == nil || !strings.Contains(err.Error(), "create temp file") {
		t.Fatalf("WriteFile error = %v, want create temp file context", err)
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
