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

func TestNewFdUnknownFlags(t *testing.T) {
        fdFile := NewFd(1, "test.txt", -1)
        if fdFile.Flags() != unknownFlag {
                t.Errorf("expected unknown flags, got %v", fdFile.Flags())
        }
}
