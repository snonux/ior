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
//
// Two publish policies exist because two kinds of names exist. Names ior
// generates itself (the timestamped defaults) use Publish/WriteFile, which
// never replace anything. A name the user typed or passed on the command line
// (-parquet <path>, a filename in a TUI modal) keeps its historical meaning
// "write exactly here, replacing what is there" through PublishReplace/
// ReplaceFile: still atomic (readers see the old or the new file, never a
// partial one), still written through an O_EXCL|O_NOFOLLOW temp file, but
// deliberately overwriting, and keeping the replaced file's permissions and
// owner. Callers that fall back to a "-N" name must tell
// the user which path was really written.
//
// Orphans: a temp file only disappears when its writer finishes or fails
// gracefully. A process that is killed or crashes mid-write leaves its
// "ior-<random>.tmp" behind, and because every call picks a fresh random name
// no later run ever reuses or cleans it. Such orphans are harmless but
// accumulate; "mage mrproper" removes *.tmp files from the working directory.
// No automatic sweep runs, since deleting *.tmp files another live ior
// process is still writing would be worse than leaving them.
package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

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
	// nameMax is the longest file name (one path component, in bytes) Linux
	// filesystems accept; a "-N" suffix must not push a name past it.
	nameMax = 255
)

// NameMax is nameMax for callers that build a file name themselves and must
// reject one that cannot fit before doing any work.
const NameMax = nameMax

// tempPrefix and tempSuffix frame the random part of a temp file name.
const (
	tempPrefix = "ior-"
	tempSuffix = ".tmp"
)

// CreateTemp creates a new, uniquely named temp file in the directory of
// final (so a later rename stays on one filesystem and is atomic) and returns
// it open for writing. The name is "ior-<16 hex digits>.tmp" - deliberately
// independent of final's name: a name derived from final ("<final>.<rand>.tmp")
// would be longer than final, so a final name near the 255-byte NAME_MAX limit
// could be created by the old code but not by its temp file. With a fixed-size
// temp name any final name the filesystem accepts can also be written.
//
// The file is created with O_EXCL|O_NOFOLLOW: it must not exist, and a
// symlink planted at the guessed name is refused rather than followed, so a
// writer running with elevated rights cannot be steered onto another file.
// The mode is 0666 filtered by the umask, exactly what os.Create gave the
// exporters before, so published files keep their previous permissions.
func CreateTemp(final string) (*os.File, error) {
	dir := filepath.Dir(final)
	var lastErr error
	for range createAttempts {
		name := filepath.Join(dir, fmt.Sprintf("%s%016x%s", tempPrefix, rand.Uint64(), tempSuffix))
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
	return publish(tmp, final, ext, renameat2NoReplace)
}

// publish is Publish with the rename syscall injected so tests can drive the
// unsupported-filesystem fallback and the error paths without a special
// filesystem.
func publish(tmp, final, ext string, rename renameFunc) (string, error) {
	for n := 0; n < publishAttempts; n++ {
		candidate := suffixed(final, ext, n)
		err := renameNoReplace(rename, tmp, candidate)
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
// before ext. When the suffixed file name would exceed NAME_MAX (255 bytes)
// the stem is truncated - on a rune boundary, so a multi-byte name never ends
// in a broken sequence - so that a near-limit name that collides still gets a
// valid "-N" name instead of failing with ENAMETOOLONG and losing the data.
func suffixed(final, ext string, n int) string {
	if n == 0 {
		return final
	}
	dir, base := filepath.Split(final)
	stem, tail := base, ""
	// The extension match is case-insensitive so "Trace.PARQUET" keeps its
	// extension last too.
	if cut := len(base) - len(ext); ext != "" && cut > 0 && strings.EqualFold(base[cut:], ext) {
		stem, tail = base[:cut], base[cut:]
	}
	tail = fmt.Sprintf("-%d%s", n, tail)
	return dir + truncateStem(stem, nameMax-len(tail)) + tail
}

// truncateStem shortens stem to at most limit bytes without splitting a UTF-8
// sequence. It returns stem unchanged when it already fits and never returns
// an empty stem for a non-empty input unless limit leaves no room at all.
func truncateStem(stem string, limit int) string {
	if len(stem) <= limit {
		return stem
	}
	if limit <= 0 {
		return ""
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(stem[cut]) {
		cut--
	}
	return stem[:cut]
}

// IsGeneratedName reports whether the file name of path is exactly a name
// ior generated from layout (a time.Format layout such as
// "ior-stream-20060102-150405.csv", extension included), as opposed to one a
// user typed. The whole base name must parse against layout: time.Parse
// requires the literal prefix and extension to match and rejects trailing
// text, and the fixed-width numeric fields (2006, 01, 02, 15, 04, 05, all
// adjacent digits) reject a malformed value such as a one-digit hour
// ("ior-stream-20260930-90500.csv" reads the hour as 90 and fails). That
// strictness relies on layout using only such fixed-width digit fields; a
// layout with variable-width elements (a bare "1", "2" or "_2") would make
// time.Parse lenient and needs its own round-trip check. Callers pass the name
// as the user gave it, before any extension is appended, so a generated name
// that lost its extension is a user-chosen name for every exporter.
func IsGeneratedName(path, layout string) bool {
	_, err := time.Parse(layout, filepath.Base(strings.TrimSpace(path)))
	return err == nil
}

// PublishReplace moves the finished temp file tmp to final, atomically
// replacing whatever is there, for names the user chose explicitly (see the
// package comment). On error tmp is left in place for the caller to remove.
//
// A rename replaces the inode, so without care replacing an existing file
// would reset its permissions to 0666&umask and its owner to the writing user
// (root under sudo), where the old truncate-in-place write kept both. When
// final is an existing regular file its permission bits are therefore copied
// onto tmp and, best effort, its owner and group (chown is refused for an
// unprivileged writer; that is not an error). A symlink at final is not a
// regular file: it is replaced by the new file and its target is left alone,
// the safe direction, since following it would let a planted link redirect
// the write. With nothing at final the new file keeps CreateTemp's
// 0666&umask.
func PublishReplace(tmp, final string) error {
	return publishReplace(tmp, final, os.Chown)
}

// chownFunc is the signature of os.Chown; it is a type so tests can observe
// the call and simulate the EPERM an unprivileged writer gets.
type chownFunc func(name string, uid, gid int) error

// publishReplace is PublishReplace with chown injected, so tests can pin that
// the existing owner is handed to the replacement (something an unprivileged
// test process cannot observe on a real file, since it can only chown to
// itself).
func publishReplace(tmp, final string, chown chownFunc) error {
	if err := inheritMode(tmp, final, chown); err != nil {
		return fmt.Errorf("publish %s as %s: %w", tmp, final, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("publish %s as %s: %w", tmp, final, err)
	}
	return nil
}

// inheritMode copies the permission bits and (best effort) owner of an
// existing regular file at final onto tmp. Anything else at final - nothing,
// a symlink, a directory - leaves tmp untouched.
func inheritMode(tmp, final string, chown chownFunc) error {
	info, err := os.Lstat(final)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		// Best effort: only root (or the owner, for a group they belong to)
		// may hand a file to another owner, so a failure is expected and
		// must not lose the recording. The order relative to chmod does not
		// matter: only the Perm() bits are copied, and chown's clearing of
		// setuid/setgid concerns bits this code never sets.
		_ = chown(tmp, int(st.Uid), int(st.Gid))
	}
	return os.Chmod(tmp, info.Mode().Perm())
}

// renameFunc is the signature of a renameat2(RENAME_NOREPLACE) call; it is a
// type so tests can substitute a filesystem that lacks the flag.
type renameFunc func(oldPath, newPath string) error

// renameat2NoReplace is the real syscall behind renameFunc.
func renameat2NoReplace(oldPath, newPath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
}

// renameNoReplace renames oldPath to newPath through rename, failing with an
// error matching fs.ErrExist when newPath already exists (a dangling symlink
// counts; it is never followed). Only the errors that mean "this kernel or
// filesystem does not implement RENAME_NOREPLACE" select the O_EXCL fallback;
// any other error (EPERM, EACCES, EXDEV, ...) is a real failure and is
// returned unchanged, because retrying it with a different mechanism would
// just fail again or, worse, mask a permission problem.
func renameNoReplace(rename renameFunc, oldPath, newPath string) error {
	err := rename(oldPath, newPath)
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

// WriteFile is the whole exporter pattern in one call for names ior generates
// itself: it creates a temp file beside final, lets write fill it, closes it
// (so a delayed write error such as a full disk surfaces here, before anything
// is published) and publishes it with Publish, never replacing an existing
// file. It returns the path the data ended up at. On any failure the temp file
// is removed and nothing is published.
func WriteFile(final, ext string, write func(io.Writer) error) (published string, err error) {
	return writeThenPublish(final, write, func(tmp string) (string, error) {
		return publish(tmp, final, ext, renameat2NoReplace)
	})
}

// ReplaceFile is WriteFile for a name the user chose explicitly: same temp
// file and atomicity, but the result atomically replaces an existing final
// (see PublishReplace). It returns final on success.
func ReplaceFile(final string, write func(io.Writer) error) (string, error) {
	return writeThenPublish(final, write, func(tmp string) (string, error) {
		return final, PublishReplace(tmp, final)
	})
}

// writeThenPublish runs the create/write/close/publish sequence shared by WriteFile
// and ReplaceFile, removing the temp file on every failure.
func writeThenPublish(final string, write func(io.Writer) error, publishTmp func(tmp string) (string, error)) (string, error) {
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
	published, err := publishTmp(tmp)
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

// Probe checks, before any expensive work has been done, that a later
// WriteFile/ReplaceFile for final can at least create its temp file: it
// creates the same kind of temp file CreateTemp does beside final and removes
// it again. A missing directory, an unwritable one (NFS root_squash, a
// read-only mount, no write permission) or a full inode table therefore
// surfaces immediately instead of after a trace that ran for minutes and had
// nothing to save. It leaves nothing behind. The temp file is created and
// removed by the same process, so it never races another ior's output.
//
// The error names the absolute directory and the bare errno text ("no such
// file or directory"), not the random temp name CreateTemp tried: that name
// means nothing to the user. The errno stays reachable through errors.Is.
func Probe(final string) error {
	f, err := CreateTemp(final)
	if err != nil {
		return fmt.Errorf("cannot create files in %s: %w", absDir(final), errnoOf(err))
	}
	return closeAndRemove(f, f.Name())
}

// ProbeReplace is Probe for a name the user chose, which PublishReplace will
// later rename over. On top of the temp-file check it rejects a final that is
// an existing directory, which the rename would refuse only at the very end,
// and it probes that the filesystem accepts the special characters (see
// RiskyNameChars) of final's base name. A symlink at final is not a
// directory here even when it points at one: rename(2) replaces the link
// itself, exactly as PublishReplace does, so Lstat (not Stat) decides. A
// dangling symlink or one pointing at a file is fine for the same reason.
func ProbeReplace(final string) error {
	if info, err := os.Lstat(final); err == nil && info.IsDir() {
		return fmt.Errorf("%s is a directory", final)
	}
	if err := Probe(final); err != nil {
		return err
	}
	if chars := RiskyNameChars(filepath.Base(final)); chars != "" {
		return ProbeNameChars(final, chars)
	}
	return nil
}

// ProbeNameChars reports whether the filesystem holding final's directory
// accepts chars inside a file name. Some filesystems reject characters Linux
// itself allows - vfat and exFAT refuse ':', '?', '*', '"', '<', '>' and '|',
// and SMB/CIFS mounts often do too - and the failure is EINVAL from the very
// call that creates the file, i.e. at the end of a long trace. Creating and
// removing a real "ior-<hex><chars>.tmp" file is the only reliable test; a
// nil result means such names can be created. The caller decides what to do
// on failure, and must tell a rejected name (IsNameRejected) from a transient
// error such as ENOSPC or EIO, which says nothing about the filesystem's
// naming rules. The error names the absolute directory and wraps the bare
// errno.
func ProbeNameChars(final, chars string) error {
	name := filepath.Join(filepath.Dir(final), fmt.Sprintf("%s%016x%s%s", tempPrefix, rand.Uint64(), chars, tempSuffix))
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o666)
	if err != nil {
		return fmt.Errorf("cannot create a file with %q in its name in %s: %w", chars, absDir(final), errnoOf(err))
	}
	return closeAndRemove(f, name)
}

// IsNameRejected reports whether err from ProbeNameChars means the
// filesystem refuses the tested characters (EINVAL, or EILSEQ for a name it
// cannot encode) as opposed to a transient failure that must not be mistaken
// for a naming rule.
func IsNameRejected(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EILSEQ)
}

// RiskyNameChars returns the distinct characters of name, in order of first
// appearance, that some filesystems (vfat, exFAT, SMB/CIFS) refuse in file
// names although Linux allows them: ':' '?' '*' '"' '<' '>' '|' '\' and the
// ASCII control characters. An empty result means name is safe everywhere
// and needs no ProbeNameChars.
func RiskyNameChars(name string) string {
	var risky []byte
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 0x20 || strings.IndexByte(`:?*"<>|\`, c) >= 0) && strings.IndexByte(string(risky), c) < 0 {
			risky = append(risky, c)
		}
	}
	return string(risky)
}

// absDir is final's directory as an absolute path for messages, so an error
// about a bare file name says which working directory was meant. When the
// working directory itself is gone it falls back to dirOf's wording.
func absDir(final string) string {
	if dir, err := filepath.Abs(filepath.Dir(final)); err == nil {
		return dir
	}
	return dirOf(final)
}

// errnoOf strips the operation and path an *fs.PathError adds, leaving the
// bare cause: the path is an internal temp name the user never chose, and the
// message already names the directory. Other errors pass through unchanged.
func errnoOf(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// dirOf is filepath.Dir spelled for messages: a bare file name lives in the
// working directory, which "." names poorly. absDir prefers the absolute
// path and uses this only when the working directory cannot be determined.
func dirOf(path string) string {
	if dir := filepath.Dir(path); dir != "." {
		return dir
	}
	return "the working directory"
}
