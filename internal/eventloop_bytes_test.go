package internal

import (
	"testing"

	"ior/internal/types"
)

func TestBytesFromRet(t *testing.T) {
	tests := []struct {
		name     string
		retEvent *types.RetEvent
		expected uint64
	}{
		{name: "nil", retEvent: nil, expected: 0},
		{
			name: "negative",
			retEvent: &types.RetEvent{
				Ret:     -1,
				RetType: types.READ_CLASSIFIED,
			},
			expected: 0,
		},
		{
			name: "zero",
			retEvent: &types.RetEvent{
				Ret:     0,
				RetType: types.READ_CLASSIFIED,
			},
			expected: 0,
		},
		{
			name: "unclassified",
			retEvent: &types.RetEvent{
				Ret:     512,
				RetType: types.UNCLASSIFIED,
			},
			expected: 0,
		},
		{
			name: "read",
			retEvent: &types.RetEvent{
				Ret:     128,
				RetType: types.READ_CLASSIFIED,
			},
			expected: 128,
		},
		{
			name: "write",
			retEvent: &types.RetEvent{
				Ret:     256,
				RetType: types.WRITE_CLASSIFIED,
			},
			expected: 256,
		},
		{
			name: "transfer",
			retEvent: &types.RetEvent{
				Ret:     1024,
				RetType: types.TRANSFER_CLASSIFIED,
			},
			expected: 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytesFromRet(tt.retEvent); got != tt.expected {
				t.Errorf("bytesFromRet() = %d, want %d", got, tt.expected)
			}
		})
	}
}
