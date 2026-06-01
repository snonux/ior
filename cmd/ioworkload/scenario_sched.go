package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// schedSchedOther is SCHED_OTHER (the default time-sharing policy, value 0). We
// only ever query against this policy; we never CHANGE the policy, so the value
// is used purely as the argument to sched_get_priority_max/min and never to set
// anything.
const schedSchedOther = 0

// schedAttrSize is the size in bytes we advertise for struct sched_attr. The
// kernel uses this field to version the struct; SCHED_ATTR_SIZE_VER0 (48) is the
// original layout and is accepted on every kernel that has sched_getattr. We
// pass a zero-initialised buffer of at least this size and let the kernel fill
// it in.
const schedAttrSize = 48

// schedParam mirrors struct sched_param: a single scheduling priority. For
// SCHED_OTHER this is always 0. We only READ it via sched_getparam, so the
// contents we pass in are irrelevant — the kernel overwrites them.
type schedParam struct {
	Priority int32
}

// schedAttr mirrors struct sched_attr as the sched_getattr syscall fills it.
// Only the Size field matters on the way in (it advertises the struct version);
// every other field is written by the kernel. We keep the full v0 layout so the
// kernel never writes past our buffer.
type schedAttr struct {
	Size       uint32
	Policy     uint32
	Flags      uint64
	Nice       int32
	Priority   uint32
	RuntimeNs  uint64
	DeadlineNs uint64
	PeriodNs   uint64
}

// schedBasic exercises the SAFE, NON-DISRUPTIVE members of the Sched syscall
// family entirely self-targeted (pid 0 == the calling thread), so it changes no
// other process and — crucially — never alters this process's scheduling state:
//
//   - sched_yield                 yields the CPU once (no lasting effect).
//   - sched_getaffinity (pid 0)   reads the current CPU affinity mask.
//   - sched_setaffinity (pid 0)   re-applies the EXACT mask just read back, so
//     the affinity is left byte-for-byte unchanged.
//   - sched_getscheduler (pid 0)  reads the current scheduling policy.
//   - sched_getparam (pid 0)      reads the current scheduling parameters.
//   - sched_getattr (pid 0)       reads the extended scheduling attributes.
//   - sched_get_priority_max/min  query the priority range for SCHED_OTHER.
//   - sched_rr_get_interval (0)   reads the round-robin quantum for this thread.
//
// INTENTIONALLY EXCLUDED (documented so the reasons travel with the code):
//   - sched_setscheduler / sched_setattr to SCHED_FIFO/SCHED_RR: require
//     CAP_SYS_NICE and would switch this thread to real-time scheduling, which
//     is disruptive and could starve the host. Only re-applying the CURRENT
//     policy/affinity (as sched_setaffinity does above) is safe, so we never
//     touch the policy at all.
//   - sched_setparam: changing scheduling parameters is only meaningful for
//     real-time policies and otherwise EINVALs under SCHED_OTHER; not worth the
//     risk for no behavioural gain.
//
// LockOSThread pins this goroutine to one OS thread so that "pid 0" (the calling
// thread) is a stable, well-defined target across every call — the affinity we
// read and re-apply, and the policy/params we query, all belong to one thread.
func schedBasic() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := schedYieldOnce(); err != nil {
		return err
	}
	if err := schedRoundtripAffinity(); err != nil {
		return err
	}
	if err := schedQueryPolicy(); err != nil {
		return err
	}
	return schedQueryPriorityRange()
}

// schedYieldOnce issues sched_yield(2) via a raw syscall (golang.org/x/sys/unix
// ships no wrapper). Yielding has no lasting effect on scheduling state.
func schedYieldOnce() error {
	if _, _, errno := syscall.RawSyscall(unix.SYS_SCHED_YIELD, 0, 0, 0); errno != 0 {
		return fmt.Errorf("sched_yield: %w", errno)
	}
	return nil
}

// schedRoundtripAffinity reads this thread's CPU affinity mask with
// sched_getaffinity(pid 0) and then writes the SAME mask back with
// sched_setaffinity(pid 0). Because we restore exactly what we read, the
// affinity is left unchanged — the call exists purely to fire the tracepoint.
func schedRoundtripAffinity() error {
	var mask unix.CPUSet
	if err := unix.SchedGetaffinity(0, &mask); err != nil {
		return fmt.Errorf("sched_getaffinity: %w", err)
	}
	// Re-apply the identical mask we just read: a no-op change.
	if err := unix.SchedSetaffinity(0, &mask); err != nil {
		return fmt.Errorf("sched_setaffinity (restore same mask): %w", err)
	}
	return nil
}

// schedQueryPolicy reads — but never modifies — this thread's scheduling policy
// and parameters via three raw syscalls (unix lacks wrappers for all three):
// sched_getscheduler, sched_getparam, and sched_getattr. Each targets pid 0 (the
// calling thread) and only fills caller-owned buffers.
func schedQueryPolicy() error {
	// sched_getscheduler returns the policy as the syscall return value; a
	// negative errno would surface as a non-zero errno here.
	if _, _, errno := syscall.RawSyscall(unix.SYS_SCHED_GETSCHEDULER, 0, 0, 0); errno != 0 {
		return fmt.Errorf("sched_getscheduler: %w", errno)
	}

	var param schedParam
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_SCHED_GETPARAM, 0, uintptr(unsafe.Pointer(&param)), 0,
	); errno != 0 {
		return fmt.Errorf("sched_getparam: %w", errno)
	}

	attr := schedAttr{Size: schedAttrSize}
	if _, _, errno := syscall.RawSyscall6(
		unix.SYS_SCHED_GETATTR,
		0,                              // pid 0: this thread
		uintptr(unsafe.Pointer(&attr)), // buffer the kernel fills in
		schedAttrSize,                  // advertised buffer size
		0,                              // flags (must be 0)
		0, 0,
	); errno != 0 {
		return fmt.Errorf("sched_getattr: %w", errno)
	}
	return nil
}

// schedQueryPriorityRange issues the remaining read-only Sched queries:
// sched_get_priority_max/min for SCHED_OTHER (the priority range, a constant
// property of the policy) and sched_rr_get_interval(pid 0) for this thread's
// round-robin time quantum. None of these change any scheduling state.
func schedQueryPriorityRange() error {
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_SCHED_GET_PRIORITY_MAX, schedSchedOther, 0, 0,
	); errno != 0 {
		return fmt.Errorf("sched_get_priority_max: %w", errno)
	}
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_SCHED_GET_PRIORITY_MIN, schedSchedOther, 0, 0,
	); errno != 0 {
		return fmt.Errorf("sched_get_priority_min: %w", errno)
	}

	// sched_rr_get_interval writes the round-robin quantum into a timespec. For
	// non-RR policies the kernel still returns a value (often the base slice),
	// so this is a harmless read.
	var ts unix.Timespec
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_SCHED_RR_GET_INTERVAL, 0, uintptr(unsafe.Pointer(&ts)), 0,
	); errno != 0 {
		return fmt.Errorf("sched_rr_get_interval: %w", errno)
	}
	return nil
}
