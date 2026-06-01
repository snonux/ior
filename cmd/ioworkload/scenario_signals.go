package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sigWaitTimeoutNsec is the rt_sigtimedwait timeout: a short 100ms so the
// scenario can never hang even if no signal is pending (e.g. if the Go runtime
// somehow consumed it first). We always send the signal to ourselves first, so
// the wait normally returns immediately.
const sigWaitTimeoutNsec = 100 * 1000 * 1000

// kernelSigsetWords is the number of 64-bit words in the kernel sigset_t that
// the rt_sig* syscalls expect. The kernel ABI uses _NSIG (64) bits, i.e. one
// 8-byte word on every Linux architecture ior targets. The rt_sig* syscalls
// take the sigset size in bytes (kernelSigsetWords*8) as their final argument.
const kernelSigsetWords = 1

// sigSetBytes is the sigset size argument the rt_sig* syscalls expect.
const sigSetBytes = kernelSigsetWords * 8

// Kernel signal-disposition and sigaltstack constants. The golang.org/x/sys
// unix package does not export these for our target version, and the kernel
// values are stable ABI, so we define them locally.
const (
	sigIgn     = 1    // SIG_IGN
	ssDisable  = 2    // SS_DISABLE
	minStackSz = 8192 // generous MINSIGSTKSZ; only needs to be valid
	siQueue    = -1   // SI_QUEUE: user-generated siginfo (negative si_code)
)

// kernelSigset is the sigset_t as the rt_sig* syscalls expect it (a fixed
// _NSIG-bit mask), distinct from the wider userspace sigset_t. We pass its
// address plus sigSetBytes to the raw syscalls.
type kernelSigset [kernelSigsetWords]uint64

func (s *kernelSigset) add(sig int) {
	// Signals are 1-based; set bit (sig-1) within the mask.
	s[(sig-1)/64] |= 1 << (uint(sig-1) % 64)
}

// kernelSigaction mirrors struct kernel_sigaction on x86_64: handler, flags,
// restorer, then the blocked-during-handler mask. We never let the handler run
// (the signal stays blocked), so the restorer is unused for SIG_IGN/SIG_DFL.
type kernelSigaction struct {
	Handler  uintptr
	Flags    uint64
	Restorer uintptr
	Mask     kernelSigset
}

// signalsBasic exercises the SIGNALS syscall family entirely self-directed, so
// it mutates no other process. The flow is made deterministic and hang-proof:
//
//   - rt_sigaction installs an ignore disposition (SIG_IGN) for SIGUSR1.
//   - rt_sigprocmask BLOCKS SIGUSR1 before we ever send it, so delivering the
//     signal to ourselves leaves it PENDING instead of running a handler or
//     killing the process.
//   - sigaltstack sets (and then disables) an alternate signal stack.
//   - kill / tgkill / tkill / rt_sigqueueinfo each send SIGUSR1 to this very
//     process/thread; because the signal is blocked these just mark it pending.
//   - rt_sigpending confirms the pending signal can be queried.
//   - rt_sigtimedwait reaps the pending SIGUSR1 with a SHORT 100ms timeout so
//     the call cannot block indefinitely.
//
// Finally the original signal mask and SIGUSR1 disposition are restored and the
// alternate stack is disabled — we leave the process as we found it.
//
// We issue the raw syscalls directly (rather than relying on the Go runtime's
// signal machinery) so the enter_/exit_ tracepoints FIRE regardless of how the
// Go runtime multiplexes its own handlers. The goal is that the syscalls are
// issued and traced, not that a user handler necessarily runs.
//
// LockOSThread pins this goroutine to one OS thread so the tid we read with
// gettid() is the tid tgkill/tkill target, and so the per-thread blocked mask
// applies to the same thread that issues the wait.
func signalsBasic() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const sig = int(unix.SIGUSR1)

	oldAct, err := installIgnoreHandler(sig)
	if err != nil {
		return err
	}
	defer restoreHandler(sig, oldAct)

	oldMask, err := blockSignal(sig)
	if err != nil {
		return err
	}
	defer restoreSignalMask(oldMask)

	if err := exerciseAltStack(); err != nil {
		return err
	}

	tid := unix.Gettid()
	pid := unix.Getpid()
	if err := sendSelfSignals(pid, tid, sig); err != nil {
		return err
	}

	if err := queryPending(); err != nil {
		return err
	}

	return reapSignal(sig)
}

// installIgnoreHandler sets SIGUSR1 to SIG_IGN via rt_sigaction and returns the
// previous disposition so it can be restored. SIG_IGN needs no restorer because
// the signal stays blocked and the disposition is never actually invoked.
func installIgnoreHandler(sig int) (kernelSigaction, error) {
	newAct := kernelSigaction{Handler: sigIgn}
	var oldAct kernelSigaction
	if _, _, errno := syscall.RawSyscall6(
		unix.SYS_RT_SIGACTION,
		uintptr(sig),
		uintptr(unsafe.Pointer(&newAct)),
		uintptr(unsafe.Pointer(&oldAct)),
		sigSetBytes,
		0, 0,
	); errno != 0 {
		return oldAct, fmt.Errorf("rt_sigaction install: %w", errno)
	}
	return oldAct, nil
}

// restoreHandler reinstalls a previously saved SIGUSR1 disposition; best-effort
// cleanup so we leave the process as we found it. If the saved action carried a
// real handler+restorer (e.g. the Go runtime's), restoring it verbatim is the
// correct behaviour.
func restoreHandler(sig int, old kernelSigaction) {
	_, _, _ = syscall.RawSyscall6(
		unix.SYS_RT_SIGACTION,
		uintptr(sig),
		uintptr(unsafe.Pointer(&old)),
		0,
		sigSetBytes,
		0, 0,
	)
}

// blockSignal adds sig to the thread's blocked set via rt_sigprocmask and
// returns the previous mask so the caller can restore it.
func blockSignal(sig int) (kernelSigset, error) {
	var newSet, oldSet kernelSigset
	newSet.add(sig)
	if _, _, errno := syscall.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_BLOCK),
		uintptr(unsafe.Pointer(&newSet)),
		uintptr(unsafe.Pointer(&oldSet)),
		sigSetBytes,
		0, 0,
	); errno != 0 {
		return oldSet, fmt.Errorf("rt_sigprocmask block: %w", errno)
	}
	return oldSet, nil
}

// restoreSignalMask reinstalls the previously saved blocked set; best-effort.
func restoreSignalMask(old kernelSigset) {
	_, _, _ = syscall.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_SETMASK),
		uintptr(unsafe.Pointer(&old)),
		0,
		sigSetBytes,
		0, 0,
	)
}

// sigaltstackT mirrors struct sigaltstack (stack_t): pointer, flags, size.
type sigaltstackT struct {
	Sp    uintptr
	Flags int32
	_     int32 // padding to 8-byte alignment for Size
	Size  uint64
}

// exerciseAltStack installs a temporary alternate signal stack via sigaltstack
// and then disables it again, so the sigaltstack tracepoint fires. The stack is
// never actually used (the signal stays blocked); it just has to be valid.
func exerciseAltStack() error {
	stackMem := make([]byte, minStackSz)
	newStack := sigaltstackT{
		Sp:    uintptr(unsafe.Pointer(&stackMem[0])),
		Flags: 0,
		Size:  uint64(len(stackMem)),
	}
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_SIGALTSTACK,
		uintptr(unsafe.Pointer(&newStack)),
		0, 0,
	); errno != 0 {
		return fmt.Errorf("sigaltstack set: %w", errno)
	}
	runtime.KeepAlive(stackMem)
	// Disable the alternate stack again to leave the thread as we found it.
	disable := sigaltstackT{Flags: ssDisable}
	_, _, _ = syscall.RawSyscall(
		unix.SYS_SIGALTSTACK,
		uintptr(unsafe.Pointer(&disable)),
		0, 0,
	)
	return nil
}

// siginfoQueue is a minimal siginfo_t for rt_sigqueueinfo. The kernel copies a
// fixed 128-byte buffer, so we pad the tail to that canonical size.
type siginfoQueue struct {
	Signo int32
	Errno int32
	Code  int32
	_     [116]byte
}

// sendSelfSignals sends SIGUSR1 to this process/thread four different ways:
// kill (process), tgkill (thread group + tid), tkill (tid), and
// rt_sigqueueinfo (process, with a siginfo payload). Because SIGUSR1 is blocked
// these only mark the signal pending; they never run a handler or kill us.
func sendSelfSignals(pid, tid, sig int) error {
	if err := unix.Kill(pid, syscall.Signal(sig)); err != nil {
		return fmt.Errorf("kill self: %w", err)
	}
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_TGKILL, uintptr(pid), uintptr(tid), uintptr(sig),
	); errno != 0 {
		return fmt.Errorf("tgkill self: %w", errno)
	}
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_TKILL, uintptr(tid), uintptr(sig), 0,
	); errno != 0 {
		return fmt.Errorf("tkill self: %w", errno)
	}
	info := siginfoQueue{Signo: int32(sig), Code: siQueue}
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_RT_SIGQUEUEINFO,
		uintptr(pid), uintptr(sig), uintptr(unsafe.Pointer(&info)),
	); errno != 0 {
		return fmt.Errorf("rt_sigqueueinfo self: %w", errno)
	}
	return nil
}

// queryPending issues rt_sigpending so its tracepoint fires; the result is not
// inspected (the wait below is what actually reaps the signal).
func queryPending() error {
	var pending kernelSigset
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_RT_SIGPENDING,
		uintptr(unsafe.Pointer(&pending)),
		sigSetBytes,
		0,
	); errno != 0 {
		return fmt.Errorf("rt_sigpending: %w", errno)
	}
	return nil
}

// reapSignal waits for the (blocked, pending) SIGUSR1 via rt_sigtimedwait with
// a short 100ms timeout. Since we already queued SIGUSR1 to ourselves, the call
// returns immediately; the timeout exists purely as a hang guard. EAGAIN (timed
// out without a pending signal) is tolerated so the scenario never fails just
// because the Go runtime consumed the pending signal first.
func reapSignal(sig int) error {
	var waitSet kernelSigset
	waitSet.add(sig)
	timeout := unix.Timespec{Sec: 0, Nsec: sigWaitTimeoutNsec}
	var info siginfoQueue
	_, _, errno := syscall.RawSyscall6(
		unix.SYS_RT_SIGTIMEDWAIT,
		uintptr(unsafe.Pointer(&waitSet)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&timeout)),
		sigSetBytes,
		0, 0,
	)
	if errno != 0 && errno != syscall.EAGAIN {
		return fmt.Errorf("rt_sigtimedwait: %w", errno)
	}
	return nil
}
