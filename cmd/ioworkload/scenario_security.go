package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var keySpecProcessKeyringArg = ^uintptr(1)

func securityKeysPtracePerf() error {
	nr, err := securitySyscallNumbers(runtime.GOARCH)
	if err != nil {
		return err
	}

	// Best-effort probes: these syscalls may fail with EPERM/EACCES depending on
	// policy, but the tracepoints are still exercised.
	runKeySyscalls(nr)
	runPtraceSyscall(nr)
	runPerfEventOpenSyscall(nr)
	return nil
}

type securitySyscalls struct {
	addKey        uintptr
	requestKey    uintptr
	keyctl        uintptr
	ptrace        uintptr
	perfEventOpen uintptr
}

func securitySyscallNumbers(arch string) (securitySyscalls, error) {
	switch arch {
	case "amd64":
		return securitySyscalls{
			addKey:        248,
			requestKey:    249,
			keyctl:        250,
			ptrace:        101,
			perfEventOpen: 298,
		}, nil
	case "arm64":
		return securitySyscalls{
			addKey:        217,
			requestKey:    218,
			keyctl:        219,
			ptrace:        117,
			perfEventOpen: 241,
		}, nil
	default:
		return securitySyscalls{}, fmt.Errorf("security syscall numbers not defined for GOARCH=%s", arch)
	}
}

func runKeySyscalls(nr securitySyscalls) {
	keyType, _ := syscall.BytePtrFromString("user")
	desc, _ := syscall.BytePtrFromString("ior-key")
	payload := []byte("ior")

	var payloadPtr uintptr
	if len(payload) > 0 {
		payloadPtr = uintptr(unsafe.Pointer(&payload[0]))
	}

	_, _, _ = syscall.Syscall6(
		nr.addKey,
		uintptr(unsafe.Pointer(keyType)),
		uintptr(unsafe.Pointer(desc)),
		payloadPtr,
		uintptr(len(payload)),
		keySpecProcessKeyringArg,
		0,
	)

	_, _, _ = syscall.Syscall6(
		nr.requestKey,
		uintptr(unsafe.Pointer(keyType)),
		uintptr(unsafe.Pointer(desc)),
		0,
		keySpecProcessKeyringArg,
		0,
		0,
	)

	_, _, _ = syscall.Syscall6(
		nr.keyctl,
		0,
		keySpecProcessKeyringArg,
		0,
		0,
		0,
		0,
	)
}

func runPtraceSyscall(nr securitySyscalls) {
	_, _, _ = syscall.Syscall6(
		nr.ptrace,
		uintptr(syscall.PTRACE_TRACEME),
		0,
		0,
		0,
		0,
		0,
	)
}

type perfEventAttr struct {
	Type   uint32
	Size   uint32
	Config uint64
}

func runPerfEventOpenSyscall(nr securitySyscalls) {
	attr := perfEventAttr{
		Type:   1, // PERF_TYPE_SOFTWARE
		Size:   uint32(unsafe.Sizeof(perfEventAttr{})),
		Config: 0, // PERF_COUNT_SW_CPU_CLOCK
	}
	fd, _, _ := syscall.Syscall6(
		nr.perfEventOpen,
		uintptr(unsafe.Pointer(&attr)),
		0,
		^uintptr(0), // cpu = -1
		^uintptr(0), // group_fd = -1
		0,
		0,
	)
	if int64(fd) >= 0 {
		_ = syscall.Close(int(fd))
	}
}
