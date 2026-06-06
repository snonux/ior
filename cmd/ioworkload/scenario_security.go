package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var keySpecProcessKeyringArg = ^uintptr(1)

// getrandomBufLen is the requested length of the getrandom buffer. getrandom
// reports the number of random bytes written into buf as its return value,
// which ior READ-classifies as a byte count.
const getrandomBufLen = 32

// securityGetrandom exercises the getrandom syscall end-to-end. getrandom
// (FamilyTime/Security, READ_CLASSIFIED) fills buf with random bytes and
// returns the count placed there, so ior records that count as the exit byte
// total.
//
// getrandom may return fewer bytes than requested only when interrupted by a
// signal; to keep the byte count deterministic we loop until the full buffer
// is filled, accumulating any short reads. The enter tracepoint is null-kind
// (no fd/path), so this scenario only locks in the READ byte-count classifi-
// cation, not a path/fd dimension.
func securityGetrandom() error {
	buf := make([]byte, getrandomBufLen)
	for off := 0; off < len(buf); {
		// Use unix.Getrandom so the exact sys_enter_getrandom tracepoint fires.
		n, err := unix.Getrandom(buf[off:], 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("getrandom: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("getrandom returned non-positive count %d", n)
		}
		off += n
	}
	return nil
}

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

// landlockAddRuleSyscallNumber is the landlock_add_rule syscall number.
// It is 445 on both amd64 and arm64 (one above landlock_create_ruleset).
func landlockAddRuleSyscallNumber(arch string) (uintptr, error) {
	switch arch {
	case "amd64", "arm64":
		return 445, nil
	default:
		return 0, fmt.Errorf("landlock_add_rule syscall number not defined for GOARCH=%s", arch)
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

// LANDLOCK_RULE_PATH_BENEATH (uapi/linux/landlock.h) — the rule type identifying
// a struct landlock_path_beneath_attr, the only rule type defined for the
// filesystem since Landlock ABI v1.
const landlockRulePathBeneath = 1

// landlockPathBeneathAttr mirrors struct landlock_path_beneath_attr
// (uapi/linux/landlock.h). allowed_access is the set of filesystem access
// rights granted beneath parent_fd, and parent_fd is an O_PATH fd to the
// directory hierarchy the rule applies to. The struct is __attribute__((packed))
// in the kernel headers, so the Go layout must match: a __u64 followed by a
// __s32 with no trailing padding.
type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
}

// securityLandlockCreateRuleset exercises the landlock_create_ruleset and
// landlock_add_rule syscalls end-to-end. It builds a minimal valid struct
// landlock_ruleset_attr (handling only LANDLOCK_ACCESS_FS_READ_FILE), calls
// landlock_create_ruleset(&attr, sizeof(attr), 0) to obtain a fresh ruleset fd,
// then adds a PATH_BENEATH rule granting READ_FILE under "/" to that ruleset,
// and finally closes both fds.
//
// SAFETY: this scenario deliberately does NOT call landlock_restrict_self.
// landlock_restrict_self irreversibly sandboxes the calling process for its
// entire lifetime, which would break the shared integration-test runner.
// landlock_create_ruleset and landlock_add_rule are unprivileged and have NO
// process-wide side effects (they only build a ruleset that is never enforced),
// so both are safe to run in-process in the shared workload.
//
// The calls are tolerated to fail with ENOSYS/EOPNOTSUPP (kernel < 5.13 or
// Landlock LSM disabled): the sys_enter tracepoints fire before any such error,
// so the tracer still observes both enter events regardless.
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

	// Always attempt landlock_add_rule, even if ruleset creation failed
	// (fd < 0). The sys_enter_landlock_add_rule tracepoint fires before the
	// kernel validates the (possibly invalid) ruleset fd, so the enter event is
	// captured unconditionally — matching how create_ruleset coverage works.
	rulesetFd := int(int64(fd))
	addLandlockReadRule(rulesetFd)

	if rulesetFd >= 0 {
		_ = syscall.Close(rulesetFd)
	}
	return nil
}

// addLandlockReadRule adds a single LANDLOCK_RULE_PATH_BENEATH rule to rulesetFd
// granting LANDLOCK_ACCESS_FS_READ_FILE beneath "/", exercising the
// landlock_add_rule(ruleset_fd, rule_type, &attr, 0) syscall end-to-end.
//
// The parent_fd must be an O_PATH descriptor to a directory; "/" always exists.
// Failures are tolerated: the sys_enter_landlock_add_rule tracepoint fires
// before any error, capturing ruleset_fd at args[0], which is the coverage goal.
func addLandlockReadRule(rulesetFd int) {
	nr, err := landlockAddRuleSyscallNumber(runtime.GOARCH)
	if err != nil {
		return
	}

	parentFd, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer syscall.Close(parentFd)

	attr := landlockPathBeneathAttr{
		allowedAccess: landlockAccessFsReadFile,
		parentFd:      int32(parentFd),
	}
	_, _, _ = syscall.Syscall6(
		nr,
		uintptr(rulesetFd),
		landlockRulePathBeneath,
		uintptr(unsafe.Pointer(&attr)),
		0, // flags = 0 (required; must be zero per the man page)
		0,
		0,
	)
}
