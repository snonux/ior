package buildgate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Large media under these prefixes is intentional (tutorial GIFs, logo source).
// Everything else tracked at HEAD must stay below maxTrackedBlobBytes, and no
// ELF binary or recording/test artifact may be tracked at all.
var intentionalLargePrefixes = []string{
	"docs/tutorial/assets/",
	"assets/",
}

const maxTrackedBlobBytes = 1 << 20 // 1 MiB

// accidentalTrackedPath is true for the workspace dumps that once bloated
// history (flamegraph.test, earth-* recordings). Matching ignore rules keep
// them out of new commits; this gate fails the suite if one is force-added.
func accidentalTrackedPath(rel string) bool {
	base := filepath.Base(rel)
	switch {
	case base == "flamegraph.test":
		return true
	case strings.HasPrefix(base, "earth-"):
		return true
	case strings.HasSuffix(base, ".ior.zst"):
		return true
	case strings.HasSuffix(base, ".collapsed"):
		return true
	case strings.HasSuffix(base, ".collapsed.zst"):
		return true
	case strings.HasSuffix(base, ".test") && !strings.HasSuffix(base, "_test.go"):
		// go test -c outputs; never source
		return true
	}
	return false
}

func intentionalLargePath(rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, p := range intentionalLargePrefixes {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

func isELF(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	var hdr [4]byte
	n, err := f.Read(hdr[:])
	if n < 4 {
		// Too short to be ELF (empty or tiny fixtures).
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return bytes.Equal(hdr[:], []byte{0x7f, 'E', 'L', 'F'}), nil
}

// TestNoAccidentalTrackedBinaries keeps clone size and history clean: no ELF
// binaries, no recording/test dumps, and no multi-MiB blobs outside the
// documented asset directories. History once held flamegraph.test (~12 MiB) and
// earth-* flamegraph dumps (~11 MiB); those paths are ignored and must stay
// untracked.
func TestNoAccidentalTrackedBinaries(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		if accidentalTrackedPath(rel) {
			t.Errorf("%s is tracked; it is a build/recording artifact (add it to .gitignore, do not commit it)", rel)
			continue
		}
		abs := filepath.Join(root, rel)
		info, err := os.Lstat(abs)
		if err != nil {
			t.Errorf("stat %s: %v", rel, err)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		elf, err := isELF(abs)
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		if elf {
			t.Errorf("%s is a tracked ELF binary; build outputs must stay gitignored", rel)
			continue
		}
		if info.Size() >= maxTrackedBlobBytes && !intentionalLargePath(rel) {
			t.Errorf("%s is %d bytes (>= %d); large blobs outside %v bloat clones — keep them out of git or under an asset prefix",
				rel, info.Size(), maxTrackedBlobBytes, intentionalLargePrefixes)
		}
	}
}
