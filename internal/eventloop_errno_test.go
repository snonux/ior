package internal

import (
	"math"
	"testing"
)

func TestFdFromRetChecksErrnoBeforeNarrowing(t *testing.T) {
	tests := []struct {
		name   string
		ret    int64
		wantFD int32
		wantOK bool
	}{
		{name: "zero", ret: 0, wantFD: 0, wantOK: true},
		{name: "highest fd", ret: math.MaxInt32, wantFD: math.MaxInt32, wantOK: true},
		{name: "errno boundary", ret: -4095, wantOK: false},
		{name: "negative non-errno is not an fd", ret: -4096, wantOK: false},
		{name: "positive truncation rejected", ret: int64(math.MaxInt32) + 1, wantOK: false},
		{name: "full-word truncation rejected", ret: 1 << 32, wantOK: false},
		{name: "maximum integer rejected", ret: math.MaxInt64, wantOK: false},
		{name: "minimum integer rejected", ret: math.MinInt64, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fd, ok := fdFromRet(tt.ret)
			if fd != tt.wantFD || ok != tt.wantOK {
				t.Fatalf("fdFromRet(%d) = (%d, %t), want (%d, %t)",
					tt.ret, fd, ok, tt.wantFD, tt.wantOK)
			}
		})
	}
}
