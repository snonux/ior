package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bpfMapCreateAttr is the reviewed prefix of union bpf_attr consumed by
// BPF_MAP_CREATE. Passing this exact size is supported by the extensible bpf
// syscall ABI; all fields after map_name remain zero for this basic array map.
type bpfMapCreateAttr struct {
	MapType               uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	InnerMapFd            uint32
	NumaNode              uint32
	MapName               [16]byte
	MapIfindex            uint32
	BtfFd                 uint32
	BtfKeyTypeID          uint32
	BtfValueTypeID        uint32
	BtfVmlinuxValueTypeID uint32
	MapExtra              uint64
}

func bpfMapCreateBasic() error {
	attr := bpfMapCreateAttr{
		MapType:    unix.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	}
	copy(attr.MapName[:], "ior_s4_map")
	fd, _, errno := syscall.RawSyscall(
		unix.SYS_BPF,
		uintptr(unix.BPF_MAP_CREATE),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno == 0 {
		// This conditional marker lets the integration test distinguish a host
		// that denied BPF_MAP_CREATE from a tracer regression that lost the
		// returned descriptor. It deliberately has no fd-state dependency.
		_, _, _ = syscall.RawSyscall(
			unix.SYS_GETPRIORITY,
			uintptr(unix.PRIO_PROCESS),
			0,
			0,
		)
		syscall.Close(int(fd))
	}
	// Capability, lockdown and LSM policy differ by host. The enter event is
	// useful even when map creation is denied, so permission errors stay benign.
	return nil
}
