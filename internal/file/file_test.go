package file

import (
	"ior/internal/types"
	"testing"
)

func TestStringValue(t *testing.T) {
	var array [128]byte
	copy(array[:], "test string")

	if str := types.StringValue(array[:]); str != "test string" {
		t.Errorf("epxected 'test string' but got '%s' with bytes '%v'", str, []byte(str))
	}
}
