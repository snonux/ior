// Package atomicfile gives every ior exporter (flamegraph .ior.zst, stream and
// snapshot CSV, parquet recordings) the same two collision-safe primitives:
// a uniquely named temp file next to the target, and a publish step that never
// replaces a file that already exists.
//
// Output names are built from a host, a user-chosen name and a timestamp that
// is only accurate to the second, so two ior runs (or two exports) in the same
// second - or the repeated local hour when DST ends - compute the identical
// name. With os.Create plus os.Rename the second writer truncated the first
// writer's temp file and then replaced its published file, silently losing a
// recording. Here the temp name is unique per call and the final name is
// claimed atomically, so a collision costs a "-N" name suffix, never data.
package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// createAttempts bounds retries when a random temp name is already taken;
	// with 64 random bits a second attempt is already vanishingly unlikely,
	// so hitting the bound signals a hostile or broken directory.
	createAttempts = 16
	// publishAttempts bounds how many "-N" suffixes Publish will try before
	// giving up on finding a free name.
	publishAttempts = 10000
)

// CreateTemp creates a new, uniquely named temp file in the directory of
// final (so a later rename stays on one filesystem and is atomic) and returns
// it open for writing. The name is "<final>.<random>.tmp".
//
// The file is created with O_EXCL|O_NOFOLLOW: it must not exist, and a
// symlink planted at the guessed name is refused rather than followed, so a
// writer running with elevated rights cannot be steered onto another file.
// The mode is 0666 filtered by the umask, exactly what os.Create gave the
// exporters before, so published files keep their previous permissions.
func CreateTemp(final string) (*os.File, error) {
	var lastErr error
	for range createAttempts {
		name := fmt.Sprintf("%s.%016x.tmp", final, rand.Uint64())
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o666)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// Publish moves the finished temp file tmp to final without replacing an
// existing file and returns the path it ended up at. When final is taken it
// tries "-1", "-2", ... inserted before ext (the extension that must stay last,
// e.g. ".ior.zst" or ".csv"; when final does not end in ext the suffix goes at
// the very end). On any error tmp is left in place for the caller to remove.
//
// The claim is atomic - renameat2(RENAME_NOREPLACE), or on filesystems
// without it an O_EXCL placeholder that is then renamed over - so two
// concurrent publishers can never pick the same name.
func Publish(tmp, final, ext string) (string, error) {
	for n := 0; n < publishAttempts; n++ {
		candidate := suffixed(final, ext, n)
		err := renameNoReplace(tmp, candidate)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("publish %s as %s: %w", tmp, candidate, err)
		}
	}
	return "", fmt.Errorf("publish %s: no free name near %s after %d attempts", tmp, final, publishAttempts)
}

// suffixed returns final for n == 0 and otherwise final with "-n" inserted
// before ext.
func suffixed(final, ext string, n int) string {
	if n == 0 {
		return final
	}
	// The extension match is case-insensitive so "Trace.PARQUET" keeps its
	// extension last too.
	if cut := len(final) - len(ext); ext != "" && cut > 0 && strings.EqualFold(final[cut:], ext) {
		return fmt.Sprintf("%s-%d%s", final[:cut], n, final[cut:])
	}
	return fmt.Sprintf("%s-%d", final, n)
}

// renameNoReplace renames oldPath to newPath, failing with an error matching
// fs.ErrExist when newPath already exists (a dangling symlink counts; it is
// never followed).
func renameNoReplace(oldPath, newPath string) error {
	err := unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST):
		return fs.ErrExist
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENOTSUP):
		// The filesystem or kernel lacks RENAME_NOREPLACE (some network and
		// FUSE filesystems).
		return claimThenRename(oldPath, newPath)
	default:
		return err
	}
}

// claimThenRename is the portable fallback: reserve newPath by creating it
// O_EXCL (atomic on every filesystem), then rename oldPath over the empty
// placeholder. Other ior publishers see the placeholder and pick another
// name; a reader may glimpse the empty file for an instant, which is the
// price of the missing atomic primitive.
func claimThenRename(oldPath, newPath string) error {
	placeholder, err := os.OpenFile(newPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o666)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fs.ErrExist
		}
		return err
	}
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	return nil
}

// WriteFile is the whole exporter pattern in one call: it creates a temp file
// beside final, lets write fill it, closes it (so a delayed write error such as
// a full disk surfaces here, before anything is published) and publishes it
// with Publish. It returns the path the data ended up at. On any failure the
// temp file is removed and nothing is published.
func WriteFile(final, ext string, write func(io.Writer) error) (published string, err error) {
	f, err := CreateTemp(final)
	if err != nil {
		return "", fmt.Errorf("create temp file for %s: %w", final, err)
	}
	tmp := f.Name()
	if err := write(f); err != nil {
		return "", errors.Join(err, closeAndRemove(f, tmp))
	}
	if err := f.Close(); err != nil {
		return "", errors.Join(fmt.Errorf("close temp file %s: %w", tmp, err), os.Remove(tmp))
	}
	published, err = Publish(tmp, final, ext)
	if err != nil {
		return "", errors.Join(err, os.Remove(tmp))
	}
	return published, nil
}

// closeAndRemove discards a half-written temp file, reporting problems other
// than the file already being gone.
func closeAndRemove(f *os.File, path string) error {
	closeErr := f.Close()
	removeErr := os.Remove(path)
	if errors.Is(removeErr, fs.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr)
}
