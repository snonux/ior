package eventstream

import "testing"

func TestResolveEditorCommandPrefersSudoEditor(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "nano")
	t.Setenv("VISUAL", "vim")
	t.Setenv("EDITOR", "nvim")

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "SUDO_EDITOR" {
		t.Fatalf("expected SUDO_EDITOR source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "nano" {
		t.Fatalf("expected nano command, got %#v", parts)
	}
}

func TestResolveEditorCommandFallsBackToVi(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")

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
