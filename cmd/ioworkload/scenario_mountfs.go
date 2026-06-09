package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type mountIDReq struct {
	Size  uint32
	Pad   uint32
	MntID uint64
	Param uint64
}

func mountfsManagement() error {
	dir, cleanup, err := makeTempDir("mountfs-management")
	if err != nil {
		return err
	}
	defer cleanup()

	mountPoint := filepath.Join(dir, "mnt")
	if err := os.Mkdir(mountPoint, 0o755); err != nil {
		return fmt.Errorf("mkdir mountpoint: %w", err)
	}

	swapFile := filepath.Join(dir, "swapfile")
	if err := os.WriteFile(swapFile, []byte("swap"), 0o600); err != nil {
		return fmt.Errorf("write swap file: %w", err)
	}

	mountPath := mustCStringPtr(mountPoint)
	swapPath := mustCStringPtr(swapFile)
	newRoot := mustCStringPtr(mountPoint)
	putOld := mustCStringPtr(dir)
	tmpfs := mustCStringPtr("tmpfs")
	none := mustCStringPtr("none")
	rootPath := mustCStringPtr("/")
	atFDCWDInt := int64(unix.AT_FDCWD)
	atFDCWD := uintptr(atFDCWDInt)

	keyName := mustCStringPtr("source")
	keyValue := mustCStringPtr("none")

	// Best-effort coverage: these calls are expected to fail on most hosts
	// without CAP_SYS_ADMIN, but still exercise syscall tracing paths. Every
	// sys_enter_ tracepoint fires on kernel entry, before any permission or
	// validity check, so the integration assertions only require the enter_
	// tracepoint to fire once (MinCount>=1) regardless of the syscall's return.
	//
	// fsopen(fsname, flags) is the entry point of the new mount API: it takes a
	// filesystem TYPE name (e.g. "tmpfs"), NOT a path, in args[0] and the
	// FSOPEN_CLOEXEC flag in args[1], returning a new filesystem-context fd. We
	// keep the returned fd to feed fsconfig below, and close it afterwards so we
	// do not leak it.
	fsContextFd := -1
	if fd, _, errno := syscall.RawSyscall(unix.SYS_FSOPEN, uintptr(unsafe.Pointer(tmpfs)), uintptr(unix.FSOPEN_CLOEXEC), 0); errno == 0 {
		fsContextFd = int(fd)
	}

	// fsconfig(fd, cmd, key, value, aux) configures a filesystem context obtained
	// from fsopen. It is a KindFd syscall: args[0] is the fscontext fd. We issue
	// two best-effort commands on whatever fd we have (the real fscontext fd when
	// fsopen succeeded, otherwise an invalid -1 which still fires the enter_
	// tracepoint and returns EBADF): FSCONFIG_SET_STRING to set a parameter and
	// FSCONFIG_CMD_CREATE to materialise the superblock. Errors (ENOSYS on old
	// kernels, EPERM/EINVAL/EBADF otherwise) are tolerated; no mount is created.
	_, _, _ = syscall.RawSyscall6(unix.SYS_FSCONFIG, uintptr(fsContextFd), uintptr(unix.FSCONFIG_SET_STRING), uintptr(unsafe.Pointer(keyName)), uintptr(unsafe.Pointer(keyValue)), 0, 0)
	_, _, _ = syscall.RawSyscall6(unix.SYS_FSCONFIG, uintptr(fsContextFd), uintptr(unix.FSCONFIG_CMD_CREATE), 0, 0, 0, 0)
	if fsContextFd >= 0 {
		_ = syscall.Close(fsContextFd)
	}

	// fspick(dfd, path, flags) creates a filesystem context for an EXISTING mount
	// so it can be reconfigured. It is a KindPathname syscall: args[1] is the path.
	// We point it at "/" (always present) with FSPICK_NO_AUTOMOUNT and close any
	// returned fscontext fd. This reconfigures nothing and creates no mount.
	if fd, _, errno := syscall.RawSyscall(unix.SYS_FSPICK, atFDCWD, uintptr(unsafe.Pointer(rootPath)), uintptr(unix.FSPICK_NO_AUTOMOUNT)); errno == 0 {
		_ = syscall.Close(int(fd))
	}

	// open_tree(dfd, path, flags) clones or references a mount subtree, returning
	// a detached O_PATH-like fd. It is a KindOpen syscall: args[0] is the dirfd.
	// We clone the scenario mount point (OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC) and
	// close any returned fd. A detached clone is not attached anywhere in the
	// mount tree, so closing the fd releases it without touching host mounts.
	if fd, _, errno := syscall.RawSyscall(unix.SYS_OPEN_TREE, atFDCWD, uintptr(unsafe.Pointer(mountPath)), uintptr(unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)); errno == 0 {
		_ = syscall.Close(int(fd))
	}

	// mount_setattr(dirfd, path, flags, attr, size) changes the per-mount
	// attributes of an existing mount. It is a KindPathname syscall: args[1] is
	// the path. We aim it at the scenario mount point with AT_FDCWD, requesting
	// MOUNT_ATTR_RDONLY, but it requires CAP_SYS_ADMIN (Linux 5.12+) and the
	// path is not even a mount here, so it returns EPERM/EINVAL unprivileged.
	// That is fine: like its mount-API siblings above, the sys_enter_
	// mount_setattr tracepoint fires on kernel entry before any permission or
	// validity check, so MinCount>=1 holds regardless of errno. attr/size carry
	// the MountAttr struct and its size so the kernel parses the call before
	// failing; the call mutates no real mount.
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
	_, _, _ = syscall.RawSyscall6(unix.SYS_MOUNT_SETATTR, atFDCWD, uintptr(unsafe.Pointer(mountPath)), 0, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)

	_, _, _ = syscall.RawSyscall6(unix.SYS_MOUNT, uintptr(unsafe.Pointer(none)), uintptr(unsafe.Pointer(mountPath)), uintptr(unsafe.Pointer(tmpfs)), 0, 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_UMOUNT2, uintptr(unsafe.Pointer(mountPath)), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_UMOUNT2, uintptr(unsafe.Pointer(mountPath)), uintptr(unix.MNT_DETACH), 0)
	_, _, _ = syscall.RawSyscall6(unix.SYS_MOVE_MOUNT, atFDCWD, uintptr(unsafe.Pointer(mountPath)), atFDCWD, uintptr(unsafe.Pointer(mountPath)), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_FSMOUNT, ^uintptr(0), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_PIVOT_ROOT, uintptr(unsafe.Pointer(newRoot)), uintptr(unsafe.Pointer(putOld)), 0)
	_, _, _ = syscall.RawSyscall6(unix.SYS_QUOTACTL, 0, uintptr(unsafe.Pointer(mountPath)), 0, 0, 0, 0)

	// quotactl_fd(fd, cmd, id, addr) is the fd-based variant of quotactl: it is
	// a KindFd syscall capturing fd@arg0. We point it at an fd opened on the
	// mount point directory with best-effort args (Q_GETQUOTA-style cmd, id 0,
	// nil addr). Quota support / privilege is irrelevant: the sys_enter_
	// quotactl_fd tracepoint fires on kernel entry before any check, exactly
	// like the quotactl call above, so MinCount>=1 holds regardless of errno.
	if quotaFd, err := syscall.Open(mountPoint, syscall.O_RDONLY, 0); err == nil {
		_, _, _ = syscall.RawSyscall6(unix.SYS_QUOTACTL_FD, uintptr(quotaFd), 0, 0, 0, 0, 0)
		_ = syscall.Close(quotaFd)
	}

	_, _, _ = syscall.RawSyscall(unix.SYS_SWAPON, uintptr(unsafe.Pointer(swapPath)), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_SWAPOFF, uintptr(unsafe.Pointer(swapPath)), 0, 0)

	req := mountIDReq{Size: uint32(unsafe.Sizeof(mountIDReq{}))}
	var statBuf [256]byte
	_, _, _ = syscall.RawSyscall6(unix.SYS_STATMOUNT, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&statBuf[0])), uintptr(len(statBuf)), 0, 0, 0)

	var mountIDs [8]uint64
	_, _, _ = syscall.RawSyscall6(unix.SYS_LISTMOUNT, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&mountIDs[0])), uintptr(len(mountIDs)), 0, 0, 0)

	if nr, err := listnsSyscallNr(); err == nil {
		var nsIDs [8]uint64
		_, _, _ = syscall.RawSyscall6(nr, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&nsIDs[0])), uintptr(len(nsIDs)), 0, 0, 0)
	}

	return nil
}

func listnsSyscallNr() (uintptr, error) {
	return listnsSyscallNrForArch(runtime.GOARCH)
}

func listnsSyscallNrForArch(arch string) (uintptr, error) {
	// __NR_listns was introduced from asm-generic numbering where amd64/arm64 use 470.
	switch arch {
	case "amd64", "arm64":
		return 470, nil
	default:
		return 0, fmt.Errorf("listns syscall number not defined for GOARCH=%s", arch)
	}
}

func mustCStringPtr(s string) *byte {
	p, _ := unix.BytePtrFromString(s)
	return p
}
