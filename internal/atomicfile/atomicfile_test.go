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
	if !strings.HasPrefix(a.Name(), final+".") || !strings.HasSuffix(a.Name(), ".tmp") {
		t.Errorf("temp name %q should be <final>.<random>.tmp", a.Name())
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
