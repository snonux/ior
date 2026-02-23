package pidpicker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanProcessesFrom(t *testing.T) {
	root := t.TempDir()

	mkProc(t, root, "12", "12 (bash) S 1 1 1 0", "bash\x00-l\x00")
	mkProc(t, root, "99", "99 (sshd) S 1 1 1 0", "")
	mkProc(t, root, "bad", "bad data", "ignored")

	processes, err := scanProcessesFrom(root)
	if err != nil {
		t.Fatalf("scanProcessesFrom returned error: %v", err)
	}

	if len(processes) != 2 {
		t.Fatalf("expected 2 valid processes, got %d", len(processes))
	}

	if processes[0].Pid != 12 || processes[0].Comm != "bash" || processes[0].Cmdline != "bash -l" {
		t.Fatalf("unexpected first process: %+v", processes[0])
	}
	if processes[1].Pid != 99 || processes[1].Comm != "sshd" || processes[1].Cmdline != "" {
		t.Fatalf("unexpected second process: %+v", processes[1])
	}
}

func TestParseCommFromStatInvalid(t *testing.T) {
	cases := []string{
		"",
		"100 no-parens",
		"100 () S 1 1 1 0",
		"100 (unterminated S 1 1 1 0",
	}

	for _, tc := range cases {
		if _, err := parseCommFromStat(tc); err == nil {
			t.Fatalf("expected parseCommFromStat to fail for %q", tc)
		}
	}
}

func TestNormalizeCmdline(t *testing.T) {
	got := normalizeCmdline([]byte("python\x00main.py\x00"))
	if got != "python main.py" {
		t.Fatalf("unexpected normalized cmdline: %q", got)
	}

	if normalizeCmdline(nil) != "" {
		t.Fatalf("expected empty cmdline for nil bytes")
	}
}

func mkProc(t *testing.T, root, pid, stat, cmdline string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
}
