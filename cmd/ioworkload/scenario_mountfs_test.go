package main

import "testing"

func TestListnsSyscallNrForArch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arch    string
		want    uintptr
		wantErr bool
	}{
		{name: "amd64", arch: "amd64", want: 470},
		{name: "arm64", arch: "arm64", want: 470},
		{name: "unsupported", arch: "riscv64", wantErr: true},
	} {
		got, err := listnsSyscallNrForArch(tc.arch)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
