package flamegraph

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

func TestBrowserOpenCommandPartsRequiresCommand(t *testing.T) {
	_, err := browserOpenCommandParts("", "http://localhost:1234/")
	if err == nil {
		t.Fatalf("expected error for empty open command")
	}
}

func TestBrowserOpenCommandPartsAppendsURLWhenMissing(t *testing.T) {
	got, err := browserOpenCommandParts("chromium --new-window", "http://localhost:1234/")
	if err != nil {
		t.Fatalf("browserOpenCommandParts returned error: %v", err)
	}
	want := []string{"chromium", "--new-window", "http://localhost:1234/"}
	if len(got) != len(want) {
		t.Fatalf("len(parts) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBrowserOpenCommandPartsReplacesURLPlaceholder(t *testing.T) {
	got, err := browserOpenCommandParts("open-browser --target={url}", "http://localhost:1234/")
	if err != nil {
		t.Fatalf("browserOpenCommandParts returned error: %v", err)
	}
	want := []string{"open-browser", "--target=http://localhost:1234/"}
	if len(got) != len(want) {
		t.Fatalf("len(parts) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMaybeOpenLiveBrowserWithoutCommandSkipsOpen(t *testing.T) {
	called := false
	orig := openBrowserURLFn
	openBrowserURLFn = func(url, openCommand string) error {
		called = true
		return nil
	}
	t.Cleanup(func() { openBrowserURLFn = orig })

	err := maybeOpenLiveBrowser("http://localhost:1234/", LiveServerOptions{})
	if err != nil {
		t.Fatalf("maybeOpenLiveBrowser returned error: %v", err)
	}
	if called {
		t.Fatalf("expected browser opener not to be called without open command")
	}
}

func TestMaybeOpenLiveBrowserWithCommandCallsOpen(t *testing.T) {
	called := false
	orig := openBrowserURLFn
	openBrowserURLFn = func(url, openCommand string) error {
		called = true
		if url != "http://localhost:1234/" {
			t.Fatalf("url = %q, want %q", url, "http://localhost:1234/")
		}
		if openCommand != "chromium" {
			t.Fatalf("openCommand = %q, want %q", openCommand, "chromium")
		}
		return nil
	}
	t.Cleanup(func() { openBrowserURLFn = orig })

	err := maybeOpenLiveBrowser("http://localhost:1234/", LiveServerOptions{
		OpenCommand: "chromium",
	})
	if err != nil {
		t.Fatalf("maybeOpenLiveBrowser returned error: %v", err)
	}
	if !called {
		t.Fatalf("expected browser opener to be called")
	}
}

func TestMaybeOpenLiveBrowserPropagatesOpenError(t *testing.T) {
	orig := openBrowserURLFn
	openBrowserURLFn = func(url, openCommand string) error {
		return errors.New("launch failed")
	}
	t.Cleanup(func() { openBrowserURLFn = orig })

	err := maybeOpenLiveBrowser("http://localhost:1234/", LiveServerOptions{
		OpenCommand: "chromium",
	})
	if err == nil || err.Error() != "launch failed" {
		t.Fatalf("expected launch failed error, got %v", err)
	}
}

func TestOpenBrowserURLReturnsErrorWhenCommandExitsNonZero(t *testing.T) {
	err := openBrowserURL("http://localhost:1234/", "false")
	if err == nil {
		t.Fatalf("expected non-nil error")
	}
}

func TestOpenBrowserURLReturnsNilWhenCommandExitsZero(t *testing.T) {
	err := openBrowserURL("http://localhost:1234/", "true")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestApplySudoInvokerContextWithEnvSetsCredential(t *testing.T) {
	cmd := exec.Command("echo")
	uid := os.Getuid()
	gid := os.Getgid()
	env := []string{
		"SUDO_UID=" + strconv.Itoa(uid),
		"SUDO_GID=" + strconv.Itoa(gid),
		"SUDO_USER=tester",
		"HOME=/root",
	}

	applySudoInvokerContextWithEnv(cmd, 0, env)

	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatalf("expected process credentials to be configured")
	}
	if got := cmd.SysProcAttr.Credential.Uid; got != uint32(uid) {
		t.Fatalf("credential uid = %d, want %d", got, uint32(uid))
	}
	if got := cmd.SysProcAttr.Credential.Gid; got != uint32(gid) {
		t.Fatalf("credential gid = %d, want %d", got, uint32(gid))
	}
	if got, ok := lookupEnvValue(cmd.Env, "USER"); !ok || got != "tester" {
		t.Fatalf("USER env = %q (ok=%v), want %q", got, ok, "tester")
	}
	if got, ok := lookupEnvValue(cmd.Env, "LOGNAME"); !ok || got != "tester" {
		t.Fatalf("LOGNAME env = %q (ok=%v), want %q", got, ok, "tester")
	}
}

func TestApplySudoInvokerContextWithEnvSkipsWhenNotRoot(t *testing.T) {
	cmd := exec.Command("echo")
	env := []string{
		"SUDO_UID=1000",
		"SUDO_GID=1000",
		"SUDO_USER=tester",
	}

	applySudoInvokerContextWithEnv(cmd, 1000, env)

	if cmd.SysProcAttr != nil {
		t.Fatalf("expected credentials to remain nil for non-root euid")
	}
	if cmd.Env != nil {
		t.Fatalf("expected environment to remain nil for non-root euid")
	}
}

func TestNotifyLiveWarningUsesCallback(t *testing.T) {
	var got string
	notifyLiveWarning(func(message string) {
		got = message
	}, "open failed")
	if got != "open failed" {
		t.Fatalf("warning callback got %q, want %q", got, "open failed")
	}
}
