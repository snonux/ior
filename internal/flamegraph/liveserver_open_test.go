package flamegraph

import (
	"errors"
	"testing"
)

func TestBrowserOpenCommandPartsUsesLinuxDefault(t *testing.T) {
	got, err := browserOpenCommandParts("linux", "", "http://localhost:1234/")
	if err != nil {
		t.Fatalf("browserOpenCommandParts returned error: %v", err)
	}
	want := []string{"firefox", "http://localhost:1234/"}
	if len(got) != len(want) {
		t.Fatalf("len(parts) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBrowserOpenCommandPartsUsesDarwinDefault(t *testing.T) {
	got, err := browserOpenCommandParts("darwin", "", "http://localhost:1234/")
	if err != nil {
		t.Fatalf("browserOpenCommandParts returned error: %v", err)
	}
	want := []string{"open", "-a", "Firefox", "http://localhost:1234/"}
	if len(got) != len(want) {
		t.Fatalf("len(parts) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBrowserOpenCommandPartsOverrideAppendsURL(t *testing.T) {
	got, err := browserOpenCommandParts("linux", "chromium --new-window", "http://localhost:1234/")
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

func TestBrowserOpenCommandPartsOverrideReplacesPlaceholder(t *testing.T) {
	got, err := browserOpenCommandParts("linux", "open-browser --target={url}", "http://localhost:1234/")
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

func TestMaybeOpenLiveBrowserDisabledSkipsOpen(t *testing.T) {
	called := false
	orig := openBrowserURLFn
	openBrowserURLFn = func(url, openCommand string) error {
		called = true
		return nil
	}
	t.Cleanup(func() { openBrowserURLFn = orig })

	err := maybeOpenLiveBrowser("http://localhost:1234/", LiveServerOptions{AutoOpenBrowser: false})
	if err != nil {
		t.Fatalf("maybeOpenLiveBrowser returned error: %v", err)
	}
	if called {
		t.Fatalf("expected browser opener not to be called when disabled")
	}
}

func TestMaybeOpenLiveBrowserEnabledCallsOpen(t *testing.T) {
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
		AutoOpenBrowser: true,
		OpenCommand:     "chromium",
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
		AutoOpenBrowser: true,
	})
	if err == nil || err.Error() != "launch failed" {
		t.Fatalf("expected launch failed error, got %v", err)
	}
}
