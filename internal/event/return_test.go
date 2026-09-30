package event

import (
	"math"
	"testing"
)

func TestIsErrnoRet(t *testing.T) {
	tests := []struct {
		name string
		ret  int64
		want bool
	}{
		{name: "zero", ret: 0, want: false},
		{name: "minus one", ret: -1, want: true},
		{name: "lowest errno", ret: -4095, want: true},
		{name: "below errno window", ret: -4096, want: false},
		{name: "maximum integer", ret: math.MaxInt64, want: false},
		{name: "minimum integer", ret: math.MinInt64, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsErrnoRet(tt.ret); got != tt.want {
				t.Fatalf("IsErrnoRet(%d) = %t, want %t", tt.ret, got, tt.want)
			}
		})
	}
}

func TestIsRestartRet(t *testing.T) {
	tests := []struct {
		name string
		ret  int64
		want bool
	}{
		{name: "ERESTARTSYS", ret: -512, want: true},
		{name: "ERESTARTNOINTR", ret: -513, want: true},
		{name: "ERESTARTNOHAND", ret: -514, want: true},
		{name: "ERESTART_RESTARTBLOCK", ret: -516, want: true},
		{name: "ENOIOCTLCMD is not a restart", ret: -515, want: false},
		{name: "below the first restart code", ret: -511, want: false},
		{name: "above the last restart code", ret: -517, want: false},
		{name: "EINTR is a real errno", ret: -4, want: false},
		{name: "positive 512 is a success value", ret: 512, want: false},
		{name: "zero", ret: 0, want: false},
		{name: "minimum integer", ret: math.MinInt64, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRestartRet(tt.ret); got != tt.want {
				t.Fatalf("IsRestartRet(%d) = %t, want %t", tt.ret, got, tt.want)
			}
		})
	}
}

// TestIsErrorRetExcludesRestartCodes pins the split between "no result"
// (IsErrnoRet, restart codes included) and "failure" (IsErrorRet).
func TestIsErrorRetExcludesRestartCodes(t *testing.T) {
	tests := []struct {
		ret       int64
		wantErrno bool
		wantError bool
	}{
		{ret: -1, wantErrno: true, wantError: true},
		{ret: -4, wantErrno: true, wantError: true},
		{ret: -511, wantErrno: true, wantError: true},
		{ret: -512, wantErrno: true, wantError: false},
		{ret: -513, wantErrno: true, wantError: false},
		{ret: -514, wantErrno: true, wantError: false},
		{ret: -515, wantErrno: true, wantError: true},
		{ret: -516, wantErrno: true, wantError: false},
		{ret: -517, wantErrno: true, wantError: true},
		{ret: -4095, wantErrno: true, wantError: true},
		{ret: -4096, wantErrno: false, wantError: false},
		{ret: 0, wantErrno: false, wantError: false},
		{ret: 7, wantErrno: false, wantError: false},
	}
	for _, tt := range tests {
		if got := IsErrnoRet(tt.ret); got != tt.wantErrno {
			t.Errorf("IsErrnoRet(%d) = %t, want %t", tt.ret, got, tt.wantErrno)
		}
		if got := IsErrorRet(tt.ret); got != tt.wantError {
			t.Errorf("IsErrorRet(%d) = %t, want %t", tt.ret, got, tt.wantError)
		}
	}
}
