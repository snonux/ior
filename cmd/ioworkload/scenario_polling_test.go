package main

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsUnsupportedEpollPwait2Err(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "enosys", err: fmt.Errorf("epoll_pwait2: %w", syscall.ENOSYS), want: true},
		{name: "enotsup", err: fmt.Errorf("epoll_pwait2: %w", syscall.ENOTSUP), want: true},
		{name: "einval", err: fmt.Errorf("epoll_pwait2: %w", syscall.EINVAL), want: false},
		{name: "opaque", err: fmt.Errorf("epoll_pwait2: not-supported"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isUnsupportedEpollPwait2Err(tt.err)
			if got != tt.want {
				t.Fatalf("isUnsupportedEpollPwait2Err(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestFdSetSetMarksBit(t *testing.T) {
	t.Parallel()

	var set fdSet
	if err := set.set(65); err != nil {
		t.Fatalf("set(65) unexpected error: %v", err)
	}
	if set[1]&(1<<1) == 0 {
		t.Fatalf("fd bit was not set: %#v", set)
	}
}

func TestFdSetSetRejectsOutOfRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fd   int
	}{
		{name: "exactly_1024", fd: 1024},
		{name: "large_fd", fd: 4096},
		{name: "negative_fd", fd: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var set fdSet
			err := set.set(tt.fd)
			if err == nil {
				t.Fatalf("set(%d) should return error, got nil", tt.fd)
			}
			if !errors.Is(err, errFDOutOfRange) {
				t.Fatalf("set(%d) error = %v, want %v", tt.fd, err, errFDOutOfRange)
			}
		})
	}
}

func TestClassicPollingSyscallsReturnReadyCount(t *testing.T) {
	var pipefd [2]int
	if err := syscall.Pipe(pipefd[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer syscall.Close(pipefd[0]) //nolint:errcheck
	defer syscall.Close(pipefd[1]) //nolint:errcheck

	waiters := []struct {
		name string
		fn   readinessWaitFn
	}{
		{name: "poll", fn: callPoll},
		{name: "ppoll", fn: callPpoll},
		{name: "select", fn: callSelect},
		{name: "pselect6", fn: callPselect6},
	}

	for _, waiter := range waiters {
		t.Run(waiter.name, func(t *testing.T) {
			if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
				t.Fatalf("write wake byte: %v", err)
			}

			ready, err := waiter.fn(pipefd)
			if err != nil {
				if isUnsupportedPollingErr(err) {
					t.Skipf("%s unsupported on this kernel: %v", waiter.name, err)
				}
				t.Fatalf("%s: %v", waiter.name, err)
			}
			if ready < 1 {
				t.Fatalf("%s ready count = %d, want >=1", waiter.name, ready)
			}

			if err := drainWakeByte(pipefd[0]); err != nil {
				t.Fatalf("drain wake byte: %v", err)
			}
		})
	}
}

func isUnsupportedPollingErr(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == syscall.ENOSYS || errno == syscall.ENOTSUP
}
