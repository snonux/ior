package flamegraph

import (
	"bytes"
	"errors"
	"os"
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
	if !strings.Contains(status.String(), "rejects ':'") {
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
