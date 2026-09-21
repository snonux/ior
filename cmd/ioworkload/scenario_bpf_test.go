package main

import (
	"testing"
	"unsafe"
)

func TestBpfMapCreateAttrMatchesUAPIPrefix(t *testing.T) {
	var attr bpfMapCreateAttr
	if got, want := unsafe.Sizeof(attr), uintptr(72); got != want {
		t.Fatalf("bpf map-create attr size = %d, want %d", got, want)
	}
	for name, gotWant := range map[string][2]uintptr{
		"map_type":    {unsafe.Offsetof(attr.MapType), 0},
		"map_name":    {unsafe.Offsetof(attr.MapName), 28},
		"map_ifindex": {unsafe.Offsetof(attr.MapIfindex), 44},
		"map_extra":   {unsafe.Offsetof(attr.MapExtra), 64},
	} {
		if gotWant[0] != gotWant[1] {
			t.Errorf("%s offset = %d, want %d", name, gotWant[0], gotWant[1])
		}
	}
}
