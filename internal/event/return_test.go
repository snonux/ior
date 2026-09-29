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
