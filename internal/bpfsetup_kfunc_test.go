package internal

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// btfBlob builds a minimal BTF blob: a header of headerLen bytes, typeBytes
// of type section and the given strings as its string section.
func btfBlob(headerLen, typeBytes int, names ...string) []byte {
	strs := []byte{0}
	for _, name := range names {
		strs = append(append(strs, name...), 0)
	}
	blob := make([]byte, headerLen+typeBytes, headerLen+typeBytes+len(strs))
	binary.LittleEndian.PutUint16(blob, btfMagic)
	blob[2] = 1
	binary.LittleEndian.PutUint32(blob[4:], uint32(headerLen))
	binary.LittleEndian.PutUint32(blob[12:], uint32(typeBytes))
	binary.LittleEndian.PutUint32(blob[16:], uint32(typeBytes))
	binary.LittleEndian.PutUint32(blob[20:], uint32(len(strs)))
	return append(blob, strs...)
}

// The kfunc is looked up as a whole string of the string section: a longer
// or shorter name is another symbol, and bytes of the type section are not
// names. What cannot be parsed counts as "has it", the answer that keeps the
// capture on.
func TestBTFNamesSymbol(t *testing.T) {
	inTypes := btfBlob(24, 0, "kiocb")
	inTypes = append(inTypes[:24:24], append([]byte("\x00bpf_rdonly_cast\x00"), inTypes[24:]...)...)
	binary.LittleEndian.PutUint32(inTypes[12:], 17)
	binary.LittleEndian.PutUint32(inTypes[16:], 17)
	otherOrder := btfBlob(24, 0, "bpf_rdonly_cast")
	otherOrder[0], otherOrder[1] = otherOrder[1], otherOrder[0]
	pastEnd := btfBlob(24, 0, "kiocb")
	binary.LittleEndian.PutUint32(pastEnd[20:], 4096)

	for _, tc := range []struct {
		name string
		blob []byte
		want bool
	}{
		{name: "named", blob: btfBlob(24, 8, "kiocb", "bpf_rdonly_cast", "task_struct"), want: true},
		{name: "named last, longer header", blob: btfBlob(32, 8, "kiocb", "bpf_rdonly_cast"), want: true},
		{name: "not named", blob: btfBlob(24, 8, "kiocb", "task_struct")},
		{name: "only a longer name", blob: btfBlob(24, 8, "bpf_rdonly_cast_impl")},
		{name: "only as the tail of a name", blob: btfBlob(24, 8, "__bpf_rdonly_cast")},
		{name: "only in the type section", blob: inTypes},
		{name: "empty string section", blob: btfBlob(24, 8)},
		{name: "truncated header", blob: btfBlob(24, 0)[:20], want: true},
		{name: "other byte order", blob: otherOrder, want: true},
		{name: "string section past the end", blob: pastEnd, want: true},
		{name: "empty", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := btfNamesSymbol(tc.blob, fileIdentKfunc); got != tc.want {
				t.Fatalf("btfNamesSymbol = %v, want %v", got, tc.want)
			}
		})
	}
}

// A BTF that cannot be read says nothing, and nothing known means the
// capture stays on; a readable one is searched.
func TestBTFFileNamesSymbol(t *testing.T) {
	dir := t.TempDir()
	if !btfFileNamesSymbol(filepath.Join(dir, "absent"), fileIdentKfunc) {
		t.Fatal("an unreadable BTF switched the capture off")
	}
	without := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(without, btfBlob(24, 8, "kiocb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if btfFileNamesSymbol(without, fileIdentKfunc) {
		t.Fatal("a BTF without the kfunc was reported to have it")
	}
}

// The running kernel's own BTF, where there is one: a name no kernel has is
// not found in it, and a kernel new enough to have the kfunc (6.2) is the
// kernel the capture was verified on.
func TestKernelBTFIsSearchable(t *testing.T) {
	if _, err := os.Stat(kernelBTFPath); err != nil {
		t.Skipf("no kernel BTF on this host: %v", err)
	}
	if btfFileNamesSymbol(kernelBTFPath, "ior_no_kernel_has_this_symbol") {
		t.Fatalf("%s is reported to name a symbol that does not exist: the search does not parse it", kernelBTFPath)
	}
	if !btfFileNamesSymbol(kernelBTFPath, "task_struct") {
		t.Fatalf("%s is reported not to name task_struct", kernelBTFPath)
	}
	t.Logf("%s present: %v", fileIdentKfunc, kernelHasFileIdentKfunc())
}

// The capture is wanted only when the environment allows it and the kernel
// can capture; the environment's typo warning is given either way.
func TestFileIdentCaptureWanted(t *testing.T) {
	for _, tc := range []struct {
		env       string
		kernelCan bool
		want      bool
		wantWarns int
	}{
		{env: "", kernelCan: true, want: true},
		{env: "", kernelCan: false},
		{env: "0", kernelCan: true},
		{env: "0", kernelCan: false},
		{env: "typo", kernelCan: false, wantWarns: 1},
		{env: "typo", kernelCan: true, want: true, wantWarns: 1},
	} {
		t.Run(fmt.Sprintf("%q kernel=%v", tc.env, tc.kernelCan), func(t *testing.T) {
			warns := 0
			got := fileIdentCaptureWanted(tc.env, func() bool { return tc.kernelCan }, func(...any) { warns++ })
			if got != tc.want || warns != tc.wantWarns {
				t.Fatalf("fileIdentCaptureWanted = %v with %d warnings, want %v with %d", got, warns, tc.want, tc.wantWarns)
			}
		})
	}
}
