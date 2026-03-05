package common

import "testing"

func TestEffectiveViewport(t *testing.T) {
	originalQuery := queryTerminalSize
	t.Cleanup(func() {
		queryTerminalSize = originalQuery
	})
	queryTerminalSize = func() (int, int, error) {
		return 132, 41, nil
	}

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
			name:       "both missing use terminal size",
			width:      0,
			height:     0,
			wantWidth:  132,
			wantHeight: 41,
		},
		{
			name:       "missing height uses terminal size",
			width:      100,
			height:     0,
			wantWidth:  100,
			wantHeight: 41,
		},
		{
			name:       "missing width uses terminal size",
			width:      -1,
			height:     30,
			wantWidth:  132,
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

func TestEffectiveViewportFallsBackToDefaultsWhenTerminalQueryFails(t *testing.T) {
	originalQuery := queryTerminalSize
	t.Cleanup(func() {
		queryTerminalSize = originalQuery
	})
	queryTerminalSize = func() (int, int, error) {
		return 0, 0, assertiveError{}
	}

	gotWidth, gotHeight := EffectiveViewport(0, 0)
	if gotWidth != defaultViewportWidth || gotHeight != defaultViewportHeight {
		t.Fatalf("got (%d,%d), want (%d,%d)", gotWidth, gotHeight, defaultViewportWidth, defaultViewportHeight)
	}
}

type assertiveError struct{}

func (assertiveError) Error() string { return "terminal query failed" }
