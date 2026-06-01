package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// miscVmspliceLen is the size of the tiny buffer vmsplice gathers into the
// pipe. It is kept far below the default pipe capacity (64 KiB) so vmsplice
// never blocks waiting for room, and we drain the read end afterwards anyway.
const miscVmspliceLen = 16

// miscBasic exercises the SAFE, UNPRIVILEGED members of the Misc syscall
// family so the enter_/exit_ tracepoints fire end-to-end. Every call here is
// read-only or self-contained: none mutate global host state, none require
// elevated capabilities, and none can block.
//
//   - getcpu   reports the CPU/NUMA node the caller runs on (raw syscall; the
//     unix package has no portable wrapper).
//   - newuname (via unix.Uname) reads the kernel/host name strings.
//   - sysinfo  (via unix.Sysinfo) reads memory/load/uptime counters.
//   - vmsplice gathers a tiny in-memory buffer into a self-created pipe; we
//     drain (and close) the pipe so it can never fill up or block.
//   - alarm(0) cancels any pending SIGALRM and returns the previous value;
//     passing 0 is harmless and arms no new timer (raw syscall; no wrapper).
//
// INTENTIONALLY EXCLUDED from this scenario (and documented here so the reasons
// travel with the code):
//   - acct, sethostname, setdomainname, syslog, fanotify_init, fanotify_mark:
//     require CAP_SYS_ADMIN and/or mutate GLOBAL host state (hostname, kernel
//     log, process accounting) — unsafe to invoke from a test workload.
//   - ioperm, iopl, modify_ldt: require CAP_SYS_RAWIO and are x86-only port/LDT
//     manipulation — privileged and non-portable.
//   - file_getattr, file_setattr: only exist on Linux 6.13+, so may be absent
//     on the kernels the integration suite runs against.
//   - rseq, get_robust_list, set_robust_list: auto-managed by the Go/C runtime
//     for restartable sequences and robust futexes; re-invoking them by hand
//     would corrupt the runtime's own registration.
//   - uprobe, uretprobe: probe-attach mechanisms, not user-callable syscalls.
func miscBasic() error {
	if err := miscGetcpu(); err != nil {
		return err
	}
	if err := miscUname(); err != nil {
		return err
	}
	if err := miscSysinfo(); err != nil {
		return err
	}
	if err := miscVmsplice(); err != nil {
		return err
	}
	return miscAlarmCancel()
}

// miscGetcpu issues getcpu(2) via a raw syscall (golang.org/x/sys/unix ships
// no portable wrapper). It writes the current CPU and NUMA node into two output
// words; the third argument (the obsolete tcache) is NULL.
func miscGetcpu() error {
	var cpu, node uint32
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_GETCPU,
		uintptr(unsafe.Pointer(&cpu)),
		uintptr(unsafe.Pointer(&node)),
		0,
	); errno != 0 {
		return fmt.Errorf("getcpu: %w", errno)
	}
	return nil
}

// miscUname issues sys_newuname (the modern uname(2)) via unix.Uname, reading
// the kernel/host identification strings into a caller-owned Utsname buffer.
func miscUname() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	return nil
}

// miscSysinfo issues sysinfo(2) via unix.Sysinfo, reading uptime/load/memory
// counters into a caller-owned Sysinfo_t buffer. Purely a read.
func miscSysinfo() error {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return fmt.Errorf("sysinfo: %w", err)
	}
	return nil
}

// miscVmsplice gathers a tiny fixed buffer into a freshly created pipe via
// vmsplice(2), then drains and closes the pipe. The buffer (miscVmspliceLen
// bytes) is far smaller than the pipe capacity, so vmsplice cannot block, and
// draining the read end leaves no descriptors or data behind.
func miscVmsplice() error {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe for vmsplice: %w", err)
	}
	readEnd, writeEnd := fds[0], fds[1]
	defer unix.Close(readEnd)
	defer unix.Close(writeEnd)

	buf := make([]byte, miscVmspliceLen)
	iov := unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
	n, _, errno := syscall.Syscall6(
		unix.SYS_VMSPLICE,
		uintptr(writeEnd),
		uintptr(unsafe.Pointer(&iov)),
		1, // one iovec
		0, // no SPLICE_F_* flags needed for this tiny, non-blocking write
		0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("vmsplice: %w", errno)
	}

	// Drain whatever vmsplice placed into the pipe so nothing lingers and the
	// pipe never approaches its capacity. A short read is fine.
	drain := make([]byte, int(n))
	if int(n) > 0 {
		if _, err := unix.Read(readEnd, drain); err != nil {
			return fmt.Errorf("drain vmsplice pipe: %w", err)
		}
	}
	return nil
}

// miscAlarmCancel issues alarm(0) via a raw syscall (no unix wrapper). Passing 0
// CANCELS any pending SIGALRM and returns the seconds remaining on the previous
// timer; it arms no new alarm, so it is entirely harmless. The previous value
// is ignored — we only care that the syscall is issued and traced.
func miscAlarmCancel() error {
	// alarm never fails; RawSyscall's errno is always 0 here.
	_, _, _ = syscall.RawSyscall(unix.SYS_ALARM, 0, 0, 0)
	return nil
}
