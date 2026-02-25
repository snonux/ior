package probemanager

import "testing"

func TestGroupTracepointsPairsEnterAndExit(t *testing.T) {
	got := GroupTracepoints([]string{
		"sys_enter_read",
		"sys_exit_read",
		"sys_enter_openat",
		"sys_exit_openat",
	})

	if len(got) != 2 {
		t.Fatalf("expected 2 grouped syscalls, got %d", len(got))
	}

	read := got["read"]
	if read.Enter != "sys_enter_read" || read.Exit != "sys_exit_read" {
		t.Fatalf("unexpected read pair: %+v", read)
	}

	openat := got["openat"]
	if openat.Enter != "sys_enter_openat" || openat.Exit != "sys_exit_openat" {
		t.Fatalf("unexpected openat pair: %+v", openat)
	}
}

func TestGroupTracepointsAllowsPartialPairs(t *testing.T) {
	got := GroupTracepoints([]string{
		"sys_enter_ioctl",
		"sys_exit_fcntl",
	})

	ioctl := got["ioctl"]
	if ioctl.Enter != "sys_enter_ioctl" || ioctl.Exit != "" {
		t.Fatalf("unexpected ioctl pair: %+v", ioctl)
	}

	fcntl := got["fcntl"]
	if fcntl.Enter != "" || fcntl.Exit != "sys_exit_fcntl" {
		t.Fatalf("unexpected fcntl pair: %+v", fcntl)
	}
}

func TestGroupTracepointsIgnoresInvalidNames(t *testing.T) {
	got := GroupTracepoints([]string{
		"sys_enter_",
		"sys_exit_",
		"random_name",
		"syscalls:sys_enter_read",
	})
	if len(got) != 0 {
		t.Fatalf("expected no grouped entries, got %+v", got)
	}
}
