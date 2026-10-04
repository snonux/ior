package flamegraph

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pinOutputEnv fixes hostname, clock and status writer, and moves into an
// empty directory, so a Prepare/Write test sees deterministic names.
func pinOutputEnv(t *testing.T) *bytes.Buffer {
	t.Helper()
	origHost, origNow, origStatus, origProbe := hostnameFn, nowFn, statusOut, probeNameChars
	t.Cleanup(func() { hostnameFn, nowFn, statusOut, probeNameChars = origHost, origNow, origStatus, origProbe })
	hostnameFn = func() (string, error) { return "host", nil }
	nowFn = func() time.Time { return time.Date(2026, 9, 30, 13, 53, 24, 0, time.UTC) }
	var status bytes.Buffer
	statusOut = &status
	t.Chdir(t.TempDir())
	return &status
}

func TestValidateName(t *testing.T) {
	for _, name := range []string{"", "default", "my trace", "a.b-c_d", "..", "ünï"} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"/tmp/mytrace", "dir/trace", "trace/", "a\x00b"} {
		err := ValidateName(name)
		if err == nil || !strings.Contains(err.Error(), "base name") {
			t.Errorf("ValidateName(%q) = %v, want a base-name error", name, err)
		}
	}
}

// TestPrepareAcceptsUsableOutputAndLeavesNoDebris covers the healthy path:
// nothing is reported, the default colon layout is kept, and the probes leave
// no temp file behind.
func TestPrepareAcceptsUsableOutputAndLeavesNoDebris(t *testing.T) {
	status := pinOutputEnv(t)
	r := NewRecorder("run")
	if err := r.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if status.Len() != 0 {
		t.Errorf("Prepare printed %q on a healthy filesystem", status.String())
	}
	if r.layout != timestampLayout {
		t.Errorf("layout = %q, want the default %q", r.layout, timestampLayout)
	}
	if entries, _ := os.ReadDir("."); len(entries) != 0 {
		t.Errorf("Prepare left %v behind", entries)
	}
}

func TestPrepareNilRecorderIsNoOp(t *testing.T) {
	var r *Recorder
	if err := r.Prepare(); err != nil {
		t.Fatalf("Prepare on nil recorder = %v, want nil", err)
	}
}

func TestPrepareRejectsPathName(t *testing.T) {
	pinOutputEnv(t)
	err := NewRecorder("/tmp/x/mytrace").Prepare()
	if err == nil || !strings.Contains(err.Error(), "base name") {
		t.Fatalf("Prepare = %v, want the base-name error", err)
	}
}

// TestPrepareRejectsUnwritableDirectory is the regression for the unwritable
// working directory that used to surface only after the whole trace. The
// directory is removed under the process, which fails the probe the same way
// as EACCES/EROFS but is also deterministic when the tests run as root.
func TestPrepareRejectsUnwritableDirectory(t *testing.T) {
	pinOutputEnv(t)
	gone := t.TempDir()
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	err := NewRecorder("run").Prepare()
	if err == nil || !strings.Contains(err.Error(), "end of the trace") {
		t.Fatalf("Prepare = %v, want the early output error", err)
	}
}

func TestPrepareRejectsTooLongName(t *testing.T) {
	pinOutputEnv(t)
	err := NewRecorder(strings.Repeat("n", 300)).Prepare()
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("Prepare = %v, want the too-long error", err)
	}
	// A name that just fits must be accepted.
	fits := 255 - len("host--2026-09-30_13:53:24.ior.zst")
	if err := NewRecorder(strings.Repeat("n", fits)).Prepare(); err != nil {
		t.Fatalf("Prepare of a name at the NAME_MAX limit = %v, want nil", err)
	}
	if err := NewRecorder(strings.Repeat("n", fits+1)).Prepare(); err == nil {
		t.Fatal("Prepare of a name one byte over NAME_MAX succeeded")
	}
}

// TestPrepareFallsBackToColonFreeTimestamp simulates a vfat/SMB directory
// (EINVAL for ':') and checks that the recording is then written under a
// colon-free name, with a note, instead of failing at the end of the trace.
func TestPrepareFallsBackToColonFreeTimestamp(t *testing.T) {
	status := pinOutputEnv(t)
	probeNameChars = func(string, string) error { return &os.PathError{Op: "open", Path: "x", Err: syscall.EINVAL} }

	r := NewRecorder("run")
	if err := r.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !strings.Contains(status.String(), "invalid argument") || !strings.Contains(status.String(), "time of day") {
		t.Errorf("status = %q, want a note about the ':' fallback", status.String())
	}
	if err := r.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat("host-run-2026-09-30_13-53-24.ior.zst"); err != nil {
		entries, _ := os.ReadDir(".")
		t.Fatalf("colon-free recording missing: %v (dir has %v)", err, entries)
	}
}

// TestPrepareKeepsColonWhenFilesystemAcceptsIt uses the real probe: on the
// ordinary test filesystem ':' works, and the recording keeps the historical
// name.
func TestPrepareKeepsColonWhenFilesystemAcceptsIt(t *testing.T) {
	pinOutputEnv(t)
	r := NewRecorder("run")
	if err := r.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := r.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat("host-run-2026-09-30_13:53:24.ior.zst"); err != nil {
		t.Fatalf("default-named recording missing: %v", err)
	}
}

// TestPrepareReportsHostnameError keeps a failing hostname lookup an early
// error too.
func TestPrepareReportsHostnameError(t *testing.T) {
	pinOutputEnv(t)
	hostnameFn = func() (string, error) { return "", errors.New("no hostname") }
	if err := NewRecorder("run").Prepare(); err == nil || !strings.Contains(err.Error(), "get hostname") {
		t.Fatalf("Prepare = %v, want the hostname error", err)
	}
}

// rejectingProbe simulates a filesystem that answers EINVAL whenever the
// probed characters include one of bad, as vfat/exFAT do for ? * " < > | :.
// The error has the shape of the real atomicfile.ProbeNameChars error (the
// characters probed, the absolute directory, the bare errno), so tests can pin
// what a user is told.
func rejectingProbe(bad string) func(string, string) error {
	return func(final, chars string) error {
		if !strings.ContainsAny(chars, bad) {
			return nil
		}
		dir, _ := filepath.Abs(filepath.Dir(final))
		return fmt.Errorf("cannot create a file with %q in its name in %s: %w", chars, dir, syscall.EINVAL)
	}
}

// TestPrepareProbesTheCharactersTheNameActuallyHas is the vfat regression for
// -name values with characters other than ':': the probe used to cover only
// ':' and the recording then failed at the final rename after the whole trace.
func TestPrepareProbesTheCharactersTheNameActuallyHas(t *testing.T) {
	status := pinOutputEnv(t)
	var probed []string
	probeNameChars = func(_, chars string) error { probed = append(probed, chars); return nil }
	if err := NewRecorder(`a?b"c`).Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(probed) != 1 || probed[0] != `?":` {
		t.Errorf("probed %q, want one probe of the characters the name really contains", probed)
	}
	if status.Len() != 0 {
		t.Errorf("unexpected status %q", status.String())
	}

	// A name without special characters still probes the time of day's ':'.
	probed = nil
	if err := NewRecorder("plain").Prepare(); err != nil || len(probed) != 1 || probed[0] != ":" {
		t.Errorf("plain name: err=%v probed=%q, want a ':' probe", err, probed)
	}
}

// TestPrepareRejectsNameCharsTheFilesystemRefuses: colon-free timestamps do
// not help when the -name itself carries a refused character, so Prepare must
// fail at startup with a message about the name.
func TestPrepareRejectsNameCharsTheFilesystemRefuses(t *testing.T) {
	status := pinOutputEnv(t)
	probeNameChars = rejectingProbe(`:?`)
	r := NewRecorder("we?rd")
	err := r.Prepare()
	if err == nil || !strings.Contains(err.Error(), `"we?rd"`) || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Prepare = %v, want an error about the -name wrapping EINVAL", err)
	}
	if r.layout != timestampLayout || status.Len() != 0 {
		t.Errorf("layout=%q status=%q: a failed Prepare must not announce a fallback", r.layout, status.String())
	}
}

// TestPrepareFallbackOnlyWhenTimeOfDayIsTheCulprit: the filesystem refuses
// ':' but accepts the name's '?': the colon-free layout cures it.
func TestPrepareFallbackOnlyWhenTimeOfDayIsTheCulprit(t *testing.T) {
	status := pinOutputEnv(t)
	probeNameChars = rejectingProbe(":")
	r := NewRecorder("a?b")
	if err := r.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if r.layout != timestampLayoutPortable || !strings.Contains(status.String(), "Note:") {
		t.Errorf("layout=%q status=%q, want the portable layout and a note", r.layout, status.String())
	}
	// The note names only ':' - the combined first probe covered ":?" and its
	// error would wrongly suggest that '?' is a problem too.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("Note: cannot create a file with \":\" in its name in %s: invalid argument; "+
		"the recording name uses '-' in the time of day instead\n", cwd)
	if status.String() != want {
		t.Errorf("status = %q, want %q", status.String(), want)
	}
}

// TestPrepareTransientProbeErrorIsReturnedNotSwallowed: ENOSPC/EIO/EMFILE
// during the probe say nothing about naming rules, so no layout switch and no
// note may hide them.
func TestPrepareTransientProbeErrorIsReturnedNotSwallowed(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOSPC, syscall.EIO, syscall.EMFILE, syscall.EDQUOT} {
		status := pinOutputEnv(t)
		probeNameChars = func(string, string) error { return &os.PathError{Op: "open", Path: "x", Err: errno} }
		r := NewRecorder("run")
		err := r.Prepare()
		if !errors.Is(err, errno) {
			t.Errorf("Prepare with %v = %v, want that errno returned", errno, err)
		}
		if r.layout != timestampLayout || status.Len() != 0 {
			t.Errorf("%v: layout=%q status=%q, want no fallback", errno, r.layout, status.String())
		}
	}
}

// TestPrepareRealProbeRejectionOnRealFilesystem drives the real (unstubbed)
// probe down its EINVAL path: a name with a NUL is refused by the kernel
// interface on every filesystem. ValidateName screens NUL in -name, so this
// calls checkNameChars directly with a sample that carries one.
func TestPrepareRealProbeRejectionOnRealFilesystem(t *testing.T) {
	pinOutputEnv(t)
	r := NewRecorder("a\x00b")
	err := r.checkNameChars("host-a\x00b-2026-09-30_13:53:24.ior.zst")
	if !errors.Is(err, syscall.EINVAL) || r.layout != timestampLayout {
		t.Fatalf("checkNameChars = %v (layout %q), want EINVAL from the real probe and no fallback", err, r.layout)
	}
}

// TestPrepareProbesNonASCIIAndInvalidBytesOfTheName: -name text that vfat
// (iocharset), ZFS utf8only or casefolded ext4 cannot encode used to reach the
// final rename unprobed. The probe must now include those runes and bytes.
func TestPrepareProbesNonASCIIAndInvalidBytesOfTheName(t *testing.T) {
	pinOutputEnv(t)
	var probed []string
	probeNameChars = func(_, chars string) error { probed = append(probed, chars); return nil }
	if err := NewRecorder("\u00fcber\xff").Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(probed) != 1 || probed[0] != ":\u00fc\xff" {
		t.Errorf("probed %q, want the ':' plus the non-ASCII rune and the invalid byte", probed)
	}
}

// TestPrepareEILSEQOnNameIsAStartupError drives the EILSEQ branch of
// IsNameRejected (no real filesystem to hand it here): the filesystem cannot
// encode the -name's text, so the colon-free layout does not help and Prepare
// must fail now, naming the -name and wrapping EILSEQ, without a note.
func TestPrepareEILSEQOnNameIsAStartupError(t *testing.T) {
	status := pinOutputEnv(t)
	probeNameChars = func(_, chars string) error {
		if strings.ContainsRune(chars, '\u00fc') {
			return &os.PathError{Op: "open", Path: "x", Err: syscall.EILSEQ}
		}
		return nil
	}
	r := NewRecorder("\u00fcber")
	err := r.Prepare()
	if !errors.Is(err, syscall.EILSEQ) || !strings.Contains(err.Error(), "-name") {
		t.Fatalf("Prepare = %v, want an error about the -name wrapping EILSEQ", err)
	}
	if r.layout != timestampLayout || status.Len() != 0 {
		t.Errorf("layout=%q status=%q: a failed Prepare must not announce a fallback", r.layout, status.String())
	}
}

// TestPrepareAcceptsInvalidUTF8NameOnRealFilesystem uses the real probe: Linux
// takes arbitrary bytes except NUL and '/', so widening the probe must not
// reject such a -name on an ordinary filesystem, and the recording must be
// writable under it.
func TestPrepareAcceptsInvalidUTF8NameOnRealFilesystem(t *testing.T) {
	status := pinOutputEnv(t)
	r := NewRecorder("bad\xff\xfe-\u00fc")
	if err := r.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if status.Len() != 0 || r.layout != timestampLayout {
		t.Errorf("status=%q layout=%q, want no note and the default layout", status.String(), r.layout)
	}
	if err := r.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat("host-bad\xff\xfe-\u00fc-2026-09-30_13:53:24.ior.zst"); err != nil {
		t.Errorf("recording with the raw-byte name missing: %v", err)
	}
}
