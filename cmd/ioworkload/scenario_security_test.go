package main

import "testing"

func TestSecuritySyscallNumbers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arch    string
		wantErr bool
		addKey  uintptr
		ptrace  uintptr
		perf    uintptr
	}{
		{name: "amd64", arch: "amd64", addKey: 248, ptrace: 101, perf: 298},
		{name: "arm64", arch: "arm64", addKey: 217, ptrace: 117, perf: 241},
		{name: "unsupported", arch: "riscv64", wantErr: true},
	} {
		got, err := securitySyscallNumbers(tc.arch)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got.addKey != tc.addKey || got.ptrace != tc.ptrace || got.perfEventOpen != tc.perf {
			t.Fatalf(
				"%s: unexpected numbers add_key=%d ptrace=%d perf_event_open=%d",
				tc.name,
				got.addKey,
				got.ptrace,
				got.perfEventOpen,
			)
		}
	}
}
