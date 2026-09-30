package internal

import (
	"errors"
	"os"
	"strings"
	"testing"

	"ior/internal/flags"
)

// TestTidFilterTgid pins how the TID_FILTER_TGID BPF global is chosen: it
// scopes the group-dead exit bypass of the tid filter to the traced thread's
// process, so it must be unset without -tid, prefer -pid, and fall back to
// "unset" (no bypass) rather than to a wrong process when procfs fails.
func TestTidFilterTgid(t *testing.T) {
	lookup := func(tgid int, err error) func(int) (int, error) {
		return func(int) (int, error) { return tgid, err }
	}
	for _, tc := range []struct {
		name     string
		pid, tid int
		readTgid func(int) (int, error)
		want     uint32
	}{
		{name: "no tid filter", pid: -1, tid: -1, readTgid: lookup(7, nil), want: noTgid},
		{name: "pid filter wins", pid: 42, tid: 43, readTgid: lookup(7, nil), want: 42},
		{name: "resolved from procfs", pid: -1, tid: 43, readTgid: lookup(42, nil), want: 42},
		{name: "procfs error", pid: -1, tid: 43, readTgid: lookup(0, errors.New("gone")), want: noTgid},
		{name: "nonsense tgid", pid: -1, tid: 43, readTgid: lookup(0, nil), want: noTgid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := flags.Config{PidFilter: tc.pid, TidFilter: tc.tid}
			if got := tidFilterTgid(cfg, tc.readTgid); got != tc.want {
				t.Fatalf("tidFilterTgid() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseStatusTgid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  string
		want    int
		wantErr bool
	}{
		{name: "thread status", status: "Name:\tworker\nTgid:\t1234\nPid:\t1240\n", want: 1234},
		{name: "missing field", status: "Name:\tworker\nPid:\t1240\n", wantErr: true},
		{name: "garbage value", status: "Tgid:\tabc\n", wantErr: true},
		{name: "empty", status: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStatusTgid(strings.NewReader(tc.status))
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseStatusTgid() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("parseStatusTgid() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestProcTgidOfOwnThread reads the real procfs entry of this process's own
// thread: a tid resolves to the tgid that owns it.
func TestProcTgidOfOwnThread(t *testing.T) {
	got, err := procTgid(os.Getpid())
	if err != nil {
		t.Fatalf("procTgid(self) error = %v", err)
	}
	if got != os.Getpid() {
		t.Fatalf("procTgid(self) = %d, want %d", got, os.Getpid())
	}
	if _, err := procTgid(-5); err == nil {
		t.Fatal("procTgid(-5) succeeded, want an error")
	}
}
