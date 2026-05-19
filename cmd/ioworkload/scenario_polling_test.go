package main

import (
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
