package main

import (
	"fmt"

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
