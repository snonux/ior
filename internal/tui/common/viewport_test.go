package common

import "testing"

func TestEffectiveViewport(t *testing.T) {
	tests := []struct {
		name       string
		width      int
		height     int
		wantWidth  int
		wantHeight int
	}{
		{
			name:       "provided dimensions",
			width:      120,
			height:     40,
			wantWidth:  120,
			wantHeight: 40,
		},
		{
			name:       "both missing use defaults",
			width:      0,
			height:     0,
			wantWidth:  defaultViewportWidth,
			wantHeight: defaultViewportHeight,
		},
		{
			name:       "missing height uses default",
			width:      100,
			height:     0,
			wantWidth:  100,
			wantHeight: defaultViewportHeight,
		},
		{
			name:       "missing width uses default",
			width:      -1,
			height:     30,
			wantWidth:  defaultViewportWidth,
			wantHeight: 30,
		},
	}

	for _, tt := range tests {
		gotWidth, gotHeight := EffectiveViewport(tt.width, tt.height)
		if gotWidth != tt.wantWidth || gotHeight != tt.wantHeight {
			t.Fatalf("%s: got (%d,%d), want (%d,%d)", tt.name, gotWidth, gotHeight, tt.wantWidth, tt.wantHeight)
		}
	}
}
