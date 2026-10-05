package buildgate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type demoFixture struct {
	root, wrapper, tape, bin, observations string
}

// These fixtures replace the renderer and privilege preflight, while exercising
// the real wrapper's paths, filesystem and process-group cleanup.
const demoRendererFixture = `#!/bin/sh
set -eu
pwd > "$IOR_TEST_OBSERVATIONS/cwd"
printf '%s\n' "$IOR_DEMO_DIR" > "$IOR_TEST_OBSERVATIONS/scratch"
readlink "$IOR_DEMO_DIR/ior" > "$IOR_TEST_OBSERVATIONS/binary"
exit "$IOR_TEST_RENDER_STATUS"
`

const demoWorkloadFixture = `#!/bin/sh
set -eu
printf '%s\n' "$$" > "$IOR_TEST_OBSERVATIONS/workload-pid"
trap 'wait || true; exit 0' TERM
sleep 60 &
printf '%s\n' "$!" > "$IOR_TEST_OBSERVATIONS/child-pid"
wait
`

const demoSudoFixture = `#!/bin/sh
printf '%s\n' "$*" >> "$IOR_TEST_OBSERVATIONS/sudo"
test "$*" = '-n true'
`

func newDemoFixture(t *testing.T) demoFixture {
	t.Helper()
	base := t.TempDir()
	f := demoFixture{root: filepath.Join(base, "repo with spaces"),
		bin: filepath.Join(base, "bin"), observations: filepath.Join(base, "observations")}
	f.wrapper = filepath.Join(f.root, "docs", "tutorial", "scripts", "run-tape.sh")
	f.tape = filepath.Join(f.root, "docs", "tutorial", "tapes", "example.tape")
	for _, dir := range []string{filepath.Dir(f.wrapper), filepath.Dir(f.tape), f.bin, f.observations} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	wrapper, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "tutorial", "scripts", "run-tape.sh"))
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, f.wrapper, string(wrapper))
	f.write(t, filepath.Join(filepath.Dir(f.wrapper), "workload.sh"), demoWorkloadFixture)
	f.write(t, filepath.Join(f.root, "ior"), "#!/bin/sh\nexit 0\n")
	f.write(t, f.tape, "")
	f.write(t, filepath.Join(f.bin, "vhs"), demoRendererFixture)
	f.write(t, filepath.Join(f.bin, "ttyd"), "#!/bin/sh\nexit 0\n")
	f.write(t, filepath.Join(f.bin, "sudo"), demoSudoFixture)
	t.Cleanup(func() {
		data, err := os.ReadFile(filepath.Join(f.observations, "workload-pid"))
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	return f
}

func TestDemoTapeCleansUpAfterRendererExit(t *testing.T) {
	for _, status := range []int{0, 42} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newDemoFixture(t)
			f.run(t, f.tape, status, status)
			if got := f.read(t, "cwd"); got != f.root {
				t.Fatalf("renderer cwd = %q, want %q", got, f.root)
			}
			if got := f.read(t, "binary"); got != filepath.Join(f.root, "ior") {
				t.Fatalf("linked binary = %q", got)
			}
			if _, err := os.Stat(f.read(t, "scratch")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("demo scratch directory survived: %v", err)
			}
			for _, name := range []string{"workload-pid", "child-pid"} {
				pid, err := strconv.Atoi(f.read(t, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
					t.Fatalf("%s was not reaped: %v", name, err)
				}
			}
			if got := f.read(t, "sudo"); got != "-n true" {
				t.Fatalf("wrapper attempted privilege calls outside preflight: %q", got)
			}
		})
	}
}

func TestDemoTapeRejectsMissingFileBeforeStartingWork(t *testing.T) {
	f := newDemoFixture(t)
	f.run(t, filepath.Join(filepath.Dir(f.tape), "missing.tape"), 0, 2)
	for _, name := range []string{"workload-pid", "scratch", "sudo"} {
		if _, err := os.Stat(filepath.Join(f.observations, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing tape started work (%s): %v", name, err)
		}
	}
}

func (f demoFixture) run(t *testing.T, tape string, renderStatus, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", f.wrapper, tape)
	cmd.Dir = t.TempDir() // Caller cwd must not determine repository paths.
	cmd.Env = append(os.Environ(), "PATH="+f.bin+":"+os.Getenv("PATH"),
		"IOR_TEST_OBSERVATIONS="+f.observations, "IOR_TEST_RENDER_STATUS="+strconv.Itoa(renderStatus))
	output, err := cmd.CombinedOutput()
	status := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run wrapper: %v\n%s", err, output)
		}
		status = exitErr.ExitCode()
	}
	if status != want {
		t.Fatalf("wrapper exit = %d, want %d\n%s", status, want, output)
	}
}

func (f demoFixture) write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
}

func (f demoFixture) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.observations, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
