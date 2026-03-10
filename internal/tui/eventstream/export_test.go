package eventstream

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEditorCommandPrefersEditor(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "nano")
	t.Setenv("VISUAL", "vim")
	t.Setenv("EDITOR", "nvim")

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "EDITOR" {
		t.Fatalf("expected EDITOR source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "nvim" {
		t.Fatalf("expected nvim command, got %#v", parts)
	}
}

func TestResolveEditorCommandFallsBackToVisualBeforeSudoEditor(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "nano")
	t.Setenv("VISUAL", "vim")
	t.Setenv("EDITOR", "")

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "VISUAL" {
		t.Fatalf("expected VISUAL source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "vim" {
		t.Fatalf("expected vim command, got %#v", parts)
	}
}

func TestResolveEditorCommandFallsBackToHxWhenAvailable(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")

	binDir := t.TempDir()
	hxPath := filepath.Join(binDir, "hx")
	if err := os.WriteFile(hxPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write hx stub: %v", err)
	}
	t.Setenv("PATH", binDir)

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "fallback" {
		t.Fatalf("expected fallback source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "hx" {
		t.Fatalf("expected hx fallback, got %#v", parts)
	}
}

func TestResolveEditorCommandFallsBackToViWhenHxMissing(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	t.Setenv("PATH", t.TempDir())

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "fallback" {
		t.Fatalf("expected fallback source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "vi" {
		t.Fatalf("expected vi fallback, got %#v", parts)
	}
}
