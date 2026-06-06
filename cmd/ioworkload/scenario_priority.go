package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// prioProcess is PRIO_PROCESS (value 0): the "which" selector telling
// get/setpriority that "who" identifies a process (rather than a process group
// or user). Paired with who == 0 it means "the calling process", so the calls
// are entirely self-targeted and need no privilege.
const prioProcess = 0

// niceOffset is the bias the kernel applies to getpriority's return value. The
// raw getpriority(2) syscall never returns a negative number (that range is
// reserved for -errno), so instead of returning the nice value directly
// (-20..19) it returns 20 - nice (i.e. 1..40). To recover the actual nice value
// we must subtract the return value from this offset. setpriority(2), by
// contrast, takes the real nice value (-20..19) directly, so we convert before
// re-applying it.
const niceOffset = 20

// priorityBasic exercises the SAFE, NON-DISRUPTIVE members of the priority pair
// (getpriority/setpriority), entirely self-targeted (PRIO_PROCESS, who 0 == the
// calling process), so it changes no other process and leaves this process's
// nice value byte-for-byte unchanged:
//
//   - getpriority(PRIO_PROCESS, 0)  reads the current nice value (a pure read).
//   - setpriority(PRIO_PROCESS, 0, currentNice)  re-applies the EXACT nice value
//     just read back, so the priority is left unchanged.
//
// Re-applying the current nice value needs no privilege: lowering the priority
// (a larger nice) is always allowed, and writing back the unchanged value is a
// no-op the kernel permits regardless of RLIMIT_NICE. This mirrors the safe
// sched_setaffinity round-trip in schedRoundtripAffinity (scenario_sched.go),
// where we likewise read a value and write the identical value straight back.
//
// Both syscalls classify as FamilyProcess with a KindNull enter (PRIO_PROCESS is
// an opcode, not an fd) and an UNCLASSIFIED return (getpriority returns a nice
// value, NOT a byte count), so the scenario exists purely to fire the enter
// tracepoints end-to-end.
func priorityBasic() error {
	// getpriority returns 20 - nice (see niceOffset); recover the real nice.
	prio, err := unix.Getpriority(prioProcess, 0)
	if err != nil {
		return fmt.Errorf("getpriority(PRIO_PROCESS, 0): %w", err)
	}
	currentNice := niceOffset - prio

	// Re-apply the IDENTICAL nice value we just read: a no-op change that needs
	// no privilege.
	if err := unix.Setpriority(prioProcess, 0, currentNice); err != nil {
		return fmt.Errorf("setpriority(PRIO_PROCESS, 0, %d) (restore same nice): %w", currentNice, err)
	}
	return nil
}

// ioprioWhoProcess is IOPRIO_WHO_PROCESS (value 1): the "which" selector telling
// ioprio_get/ioprio_set that "who" identifies a single process (rather than a
// process group or user). Paired with who == 0 it means "the calling process",
// so the calls are entirely self-targeted and need no privilege.
const ioprioWhoProcess = 1

// ioprioClassShift is the bit position of the I/O-priority class within the
// 16-bit ioprio value: the top 3 bits hold the class, the low 13 bits the level.
// IOPRIO_PRIO_VALUE(class, level) == (class << ioprioClassShift) | level.
const ioprioClassShift = 13

// ioprioClassBE is IOPRIO_CLASS_BE (value 2), the best-effort scheduling class.
// Setting best-effort on SELF is unprivileged; the realtime class
// (IOPRIO_CLASS_RT == 1) would require CAP_SYS_ADMIN, so we never use it.
const ioprioClassBE = 2

// ioprioBasic exercises the SAFE, NON-DISRUPTIVE I/O-priority pair
// (ioprio_get/ioprio_set), the I/O analogues of getpriority/setpriority. There
// is no x/sys wrapper for these, so we issue the raw syscalls directly. Both are
// self-targeted (IOPRIO_WHO_PROCESS, who 0 == the calling process), so they
// affect no other process:
//
//   - ioprio_get(IOPRIO_WHO_PROCESS, 0)  READS the current I/O priority. The
//     return is a packed (class<<13)|level value, or 0 when none is set (the
//     process inherits a default derived from its CPU nice value).
//   - ioprio_set(IOPRIO_WHO_PROCESS, 0, value)  re-applies the value just read.
//     If ioprio_get returned 0 (no explicit priority), we instead set best-effort
//     level 4 — a harmless, unprivileged choice. Best-effort needs no privilege;
//     we deliberately avoid the realtime class, which needs CAP_SYS_ADMIN.
//
// Both syscalls classify as FamilyProcess with a KindNull enter (IOPRIO_WHO_*
// is an opcode, not an fd) and an UNCLASSIFIED return (the value is an
// I/O-priority word, NOT a byte count), so the scenario exists purely to fire
// the enter tracepoints end-to-end, mirroring priorityBasic above.
func ioprioBasic() error {
	// ioprio_get returns -1/errno on failure, else the packed priority (>= 0).
	ret, _, errno := syscall.Syscall(unix.SYS_IOPRIO_GET, ioprioWhoProcess, 0, 0)
	if errno != 0 {
		return fmt.Errorf("ioprio_get(IOPRIO_WHO_PROCESS, 0): %w", errno)
	}

	ioprioValue := uintptr(ret)
	if ioprioValue == 0 {
		// No explicit I/O priority is set; choose a harmless best-effort value
		// (class BE, level 4) so ioprio_set has a valid, unprivileged argument.
		ioprioValue = uintptr(ioprioClassBE<<ioprioClassShift | 4)
	}

	// Re-apply the value we just read (or the safe best-effort default): a
	// non-disruptive, unprivileged self-update.
	_, _, errno = syscall.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprioValue)
	if errno != 0 {
		return fmt.Errorf("ioprio_set(IOPRIO_WHO_PROCESS, 0, %#x): %w", ioprioValue, errno)
	}
	return nil
}
