package flamegraph

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ior/internal/types"

	"github.com/DataDog/zstd"
)

func writeTestIorZst(t *testing.T, dir string) string {
	t.Helper()

	iod := newIorData()
	iod.add("/tmp/test", types.SYS_ENTER_OPENAT, "tester", 100, 200, flagsType(syscall.O_RDONLY), Counter{
		Count:          1,
		Duration:       10,
		DurationToPrev: 2,
		Bytes:          0,
	})
	serialized, err := iod.serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	path := filepath.Join(dir, "sample.ior.zst")
	fd, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test ior file: %v", err)
	}
	defer fd.Close()

	enc := zstd.NewWriter(fd)
	if _, err := enc.Write(serialized); err != nil {
		t.Fatalf("write zstd payload: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close zstd writer: %v", err)
	}

	return path
}

func TestWriteSVGFromFileCleansUpPartialOutputOnError(t *testing.T) {
	dir := t.TempDir()
	iorFile := writeTestIorZst(t, dir)

	n := NewNativeSVG([]string{"invalidField"}, "count")
	outFile, err := n.WriteSVGFromFile(iorFile)
	if err == nil {
		t.Fatal("expected error for invalid field, got nil")
	}

	if _, statErr := os.Stat(outFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected partial output to be removed, stat err=%v", statErr)
	}
}
