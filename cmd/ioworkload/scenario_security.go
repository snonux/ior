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
		uintptr(syscall.PTRACE_PEEKDATA),
		^uintptr(0),
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

// landlockSyscallNumber is the landlock_create_ruleset syscall number.
// It is 444 on both amd64 and arm64 (and most modern arches).
func landlockSyscallNumber(arch string) (uintptr, error) {
	switch arch {
	case "amd64", "arm64":
		return 444, nil
	default:
		return 0, fmt.Errorf("landlock_create_ruleset syscall number not defined for GOARCH=%s", arch)
	}
}

// landlockRulesetAttr mirrors struct landlock_ruleset_attr (uapi/linux/landlock.h).
// handled_access_fs is the set of filesystem access rights the ruleset will
// govern; handled_access_net (added in Landlock ABI v4) governs TCP access.
// We declare both fields so unsafe.Sizeof yields the current kernel struct size.
type landlockRulesetAttr struct {
	handledAccessFs  uint64
	handledAccessNet uint64
}

// LANDLOCK_ACCESS_FS_READ_FILE (uapi/linux/landlock.h) — a benign, always-valid
// filesystem access right used to populate a minimal, valid ruleset attribute.
const landlockAccessFsReadFile = 0x4

// securityLandlockCreateRuleset exercises the landlock_create_ruleset syscall
// end-to-end. It builds a minimal valid struct landlock_ruleset_attr (handling
// only LANDLOCK_ACCESS_FS_READ_FILE), calls landlock_create_ruleset(&attr,
// sizeof(attr), 0) to obtain a fresh ruleset fd, and closes it.
//
// SAFETY: this scenario deliberately does NOT call landlock_restrict_self.
// landlock_restrict_self irreversibly sandboxes the calling process for its
// entire lifetime, which would break the shared integration-test runner.
// Creating and closing a ruleset fd has no process-wide side effects.
//
// The call is tolerated to fail with ENOSYS/EOPNOTSUPP (kernel < 5.13 or
// Landlock LSM disabled): the sys_enter_landlock_create_ruleset tracepoint
// fires before any such error, so the tracer still observes the enter event.
func securityLandlockCreateRuleset() error {
	nr, err := landlockSyscallNumber(runtime.GOARCH)
	if err != nil {
		return err
	}

	attr := landlockRulesetAttr{
		handledAccessFs: landlockAccessFsReadFile,
	}
	fd, _, _ := syscall.Syscall(
		nr,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0, // flags = 0: create a real ruleset (not the ABI-version query)
	)
	if int64(fd) >= 0 {
		_ = syscall.Close(int(fd))
	}
	return nil
}
