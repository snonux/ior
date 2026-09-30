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

// mountfsPaths holds the scenario's filesystem fixtures.
type mountfsPaths struct {
	dir                  string
	mountPoint           string
	openTreeTarget       string
	moveMountDestination string
	swapFile             string
}

// atFDCWDInt / atFDCWD carry AT_FDCWD as a raw syscall argument. The
// negative constant cannot be converted to uintptr at compile time, so it goes
// through a typed int64 variable, which sign-extends it at run time.
var (
	atFDCWDInt int64 = unix.AT_FDCWD
	atFDCWD          = uintptr(atFDCWDInt)
)

// mountfsManagement exercises the mount / filesystem-management syscall
// family. The helpers run in a fixed order and each keeps its own syscalls in
// the original order, because the integration tests assert on this sequence.
//
// Best-effort coverage: most calls are expected to fail on hosts without
// CAP_SYS_ADMIN, but still exercise syscall tracing paths. Every sys_enter_
// tracepoint fires on kernel entry, before any permission or validity check,
// so the integration assertions only require the enter_ tracepoint to fire
// once (MinCount>=1) regardless of the syscall's return.
func mountfsManagement() error {
	dir, cleanup, err := makeTempDir("mountfs-management")
	if err != nil {
		return err
	}
	defer cleanup()

	paths, err := prepareMountfsPaths(dir)
	if err != nil {
		return err
	}
	if err := mountfsNewMountAPI(paths); err != nil {
		return err
	}
	mountfsPickAndOpenTree(paths)
	mountfsLegacyMountCalls(paths)
	mountfsListCalls()
	return nil
}

// prepareMountfsPaths creates the mount point, open_tree target, move_mount
// destination directories and the swap file below dir.
func prepareMountfsPaths(dir string) (mountfsPaths, error) {
	p := mountfsPaths{
		dir:                  dir,
		mountPoint:           filepath.Join(dir, "mnt"),
		openTreeTarget:       filepath.Join(dir, "open-tree-target"),
		moveMountDestination: filepath.Join(dir, "move-mount-destination"),
		swapFile:             filepath.Join(dir, "swapfile"),
	}
	if err := os.Mkdir(p.mountPoint, 0o755); err != nil {
		return p, fmt.Errorf("mkdir mountpoint: %w", err)
	}
	if err := os.Mkdir(p.openTreeTarget, 0o755); err != nil {
		return p, fmt.Errorf("mkdir open_tree target: %w", err)
	}
	if err := os.Mkdir(p.moveMountDestination, 0o755); err != nil {
		return p, fmt.Errorf("mkdir move_mount destination: %w", err)
	}
	if err := os.WriteFile(p.swapFile, []byte("swap"), 0o600); err != nil {
		return p, fmt.Errorf("write swap file: %w", err)
	}
	return p, nil
}

// mountfsNewMountAPI drives fsopen -> fsconfig -> fsmount -> move_mount and
// closes the filesystem-context fd afterwards (also on the error path).
func mountfsNewMountAPI(p mountfsPaths) error {
	fsContextFd := mountfsOpenAndConfigure()
	err := mountfsMountAndMove(p, fsContextFd)
	if fsContextFd >= 0 {
		syscall.Close(fsContextFd)
	}
	return err
}

// mountfsOpenAndConfigure opens a tmpfs filesystem context and configures it,
// returning the context fd or -1 when fsopen failed.
//
// fsopen(fsname, flags) is the entry point of the new mount API: it takes a
// filesystem TYPE name (e.g. "tmpfs"), NOT a path, in args[0] and the
// FSOPEN_CLOEXEC flag in args[1], returning a new filesystem-context fd. The
// caller keeps the returned fd to feed fsmount and closes it afterwards so it
// does not leak.
//
// fsconfig(fd, cmd, key, value, aux) configures a filesystem context obtained
// from fsopen. It is a KindFd syscall: args[0] is the fscontext fd. We issue
// two best-effort commands on whatever fd we have (the real fscontext fd when
// fsopen succeeded, otherwise an invalid -1 which still fires the enter_
// tracepoint and returns EBADF): FSCONFIG_SET_STRING to set a parameter and
// FSCONFIG_CMD_CREATE to materialise the superblock. Errors (ENOSYS on old
// kernels, EPERM/EINVAL/EBADF otherwise) are tolerated; no mount is created.
func mountfsOpenAndConfigure() int {
	tmpfs := mustCStringPtr("tmpfs")
	keyName := mustCStringPtr("source")
	keyValue := mustCStringPtr("none")

	fsContextFd := -1
	if fd, _, errno := syscall.RawSyscall(unix.SYS_FSOPEN, uintptr(unsafe.Pointer(tmpfs)), uintptr(unix.FSOPEN_CLOEXEC), 0); errno == 0 {
		fsContextFd = int(fd)
	}
	_, _, _ = syscall.RawSyscall6(unix.SYS_FSCONFIG, uintptr(fsContextFd), uintptr(unix.FSCONFIG_SET_STRING), uintptr(unsafe.Pointer(keyName)), uintptr(unsafe.Pointer(keyValue)), 0, 0)
	_, _, _ = syscall.RawSyscall6(unix.SYS_FSCONFIG, uintptr(fsContextFd), uintptr(unix.FSCONFIG_CMD_CREATE), 0, 0, 0, 0)
	return fsContextFd
}

// mountfsMountAndMove calls fsmount on the filesystem context and then
// move_mount.
//
// fsmount consumes the live filesystem-context fd and returns a detached
// mount fd. On capable hosts, immediately feed that fd to move_mount using
// MOVE_MOUNT_F_EMPTY_PATH and a distinct destination. If creation fails,
// still issue move_mount with two pathnames so its enter event always carries
// an independently assertable destination rather than the old same-path pair.
func mountfsMountAndMove(p mountfsPaths, fsContextFd int) error {
	moveMountDestinationPath := mustCStringPtr(p.moveMountDestination)

	mountFd := -1
	if fd, _, errno := syscall.RawSyscall(unix.SYS_FSMOUNT, uintptr(fsContextFd), uintptr(unix.FSMOUNT_CLOEXEC), 0); errno == 0 {
		mountFd = int(fd)
	}
	if mountFd < 0 {
		mountPath := mustCStringPtr(p.mountPoint)
		_, _, _ = syscall.RawSyscall6(
			unix.SYS_MOVE_MOUNT,
			atFDCWD,
			uintptr(unsafe.Pointer(mountPath)),
			atFDCWD,
			uintptr(unsafe.Pointer(moveMountDestinationPath)),
			0,
			0,
		)
		return nil
	}
	defer syscall.Close(mountFd)
	return moveDetachedMount(mountFd, moveMountDestinationPath)
}

// moveDetachedMount attaches the detached mount fd at destination via
// move_mount(MOVE_MOUNT_F_EMPTY_PATH). When that succeeds the tmpfs is now in
// the host mount namespace, so it is lazily unmounted again before the
// scenario's RemoveAll tries to remove the workload directory.
func moveDetachedMount(mountFd int, destination *byte) error {
	emptyPath := mustCStringPtr("")
	_, _, moveErrno := syscall.RawSyscall6(
		unix.SYS_MOVE_MOUNT,
		uintptr(mountFd),
		uintptr(unsafe.Pointer(emptyPath)),
		atFDCWD,
		uintptr(unsafe.Pointer(destination)),
		uintptr(unix.MOVE_MOUNT_F_EMPTY_PATH),
		0,
	)
	if moveErrno != 0 {
		return nil
	}
	_, _, unmountErrno := syscall.RawSyscall(
		unix.SYS_UMOUNT2,
		uintptr(unsafe.Pointer(destination)),
		uintptr(unix.MNT_DETACH),
		0,
	)
	if unmountErrno != 0 {
		return fmt.Errorf("unmount move_mount destination: %w", unmountErrno)
	}
	return nil
}

// mountfsPickAndOpenTree covers fspick, open_tree and open_tree_attr, closing
// every descriptor they return.
func mountfsPickAndOpenTree(p mountfsPaths) {
	rootPath := mustCStringPtr("/")
	openTreePath := mustCStringPtr(p.openTreeTarget)

	// fspick(dfd, path, flags) creates a filesystem context for an EXISTING mount
	// so it can be reconfigured. It is a KindPathname syscall: args[1] is the path.
	// We point it at "/" (always present) with FSPICK_NO_AUTOMOUNT and close any
	// returned fscontext fd. This reconfigures nothing and creates no mount.
	if fd, _, errno := syscall.RawSyscall(unix.SYS_FSPICK, atFDCWD, uintptr(unsafe.Pointer(rootPath)), uintptr(unix.FSPICK_NO_AUTOMOUNT|unix.FSPICK_CLOEXEC)); errno == 0 {
		// A successful fspick returns an fscontext descriptor. Feed it to
		// fsconfig before close so integration runs on capable hosts exercise
		// the complete fspick -> fd consumer -> close state chain.
		_, _, _ = syscall.RawSyscall6(unix.SYS_FSCONFIG, fd, uintptr(unix.FSCONFIG_CMD_RECONFIGURE), 0, 0, 0, 0)
		syscall.Close(int(fd))
	}

	// open_tree(dfd, path, flags) returns an O_PATH-like fd. Use a dedicated
	// pathname and non-cloning flags so the call succeeds without CAP_SYS_ADMIN;
	// the AT_* bits deliberately overlap unrelated O_* bits and exercise ior's
	// translation of the mount-API word before descriptor registration.
	openTreeFlags := unix.OPEN_TREE_CLOEXEC | unix.AT_NO_AUTOMOUNT | unix.AT_SYMLINK_NOFOLLOW
	if fd, _, errno := syscall.RawSyscall(unix.SYS_OPEN_TREE, atFDCWD, uintptr(unsafe.Pointer(openTreePath)), uintptr(openTreeFlags)); errno == 0 {
		syscall.Close(int(fd))
	}

	// open_tree_attr is the Linux 6.15 sibling that adds mount_attr/size. It
	// shares open_tree's path and flags positions, so issue it best-effort even
	// on older kernels (where it returns ENOSYS) to cover its generated handler.
	openTreeAttr := unix.MountAttr{}
	if fd, _, errno := syscall.RawSyscall6(unix.SYS_OPEN_TREE_ATTR, atFDCWD, uintptr(unsafe.Pointer(openTreePath)), uintptr(unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC), uintptr(unsafe.Pointer(&openTreeAttr)), unsafe.Sizeof(openTreeAttr), 0); errno == 0 {
		syscall.Close(int(fd))
	}
}

// mountfsLegacyMountCalls covers mount_setattr, the classic mount/umount2/
// pivot_root/quotactl calls, quotactl_fd and swapon/swapoff. None of them is
// expected to succeed unprivileged; only their enter tracepoints matter.
func mountfsLegacyMountCalls(p mountfsPaths) {
	mountPath := mustCStringPtr(p.mountPoint)
	newRoot := mustCStringPtr(p.mountPoint)
	putOld := mustCStringPtr(p.dir)
	tmpfs := mustCStringPtr("tmpfs")
	none := mustCStringPtr("none")
	swapPath := mustCStringPtr(p.swapFile)

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
	_, _, _ = syscall.RawSyscall(unix.SYS_PIVOT_ROOT, uintptr(unsafe.Pointer(newRoot)), uintptr(unsafe.Pointer(putOld)), 0)
	_, _, _ = syscall.RawSyscall6(unix.SYS_QUOTACTL, 0, uintptr(unsafe.Pointer(mountPath)), 0, 0, 0, 0)

	// quotactl_fd(fd, cmd, id, addr) is the fd-based variant of quotactl: it is
	// a KindFd syscall capturing fd@arg0. We point it at an fd opened on the
	// mount point directory with best-effort args (Q_GETQUOTA-style cmd, id 0,
	// nil addr). Quota support / privilege is irrelevant: the sys_enter_
	// quotactl_fd tracepoint fires on kernel entry before any check, exactly
	// like the quotactl call above, so MinCount>=1 holds regardless of errno.
	if quotaFd, err := syscall.Open(p.mountPoint, syscall.O_RDONLY, 0); err == nil {
		_, _, _ = syscall.RawSyscall6(unix.SYS_QUOTACTL_FD, uintptr(quotaFd), 0, 0, 0, 0, 0)
		syscall.Close(quotaFd)
	}

	_, _, _ = syscall.RawSyscall(unix.SYS_SWAPON, uintptr(unsafe.Pointer(swapPath)), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_SWAPOFF, uintptr(unsafe.Pointer(swapPath)), 0, 0)
}

// mountfsListCalls covers statmount, listmount and (where its syscall number
// is known) listns with a zero mount-id request.
func mountfsListCalls() {
	req := mountIDReq{Size: uint32(unsafe.Sizeof(mountIDReq{}))}
	var statBuf [256]byte
	_, _, _ = syscall.RawSyscall6(unix.SYS_STATMOUNT, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&statBuf[0])), uintptr(len(statBuf)), 0, 0, 0)

	var mountIDs [8]uint64
	_, _, _ = syscall.RawSyscall6(unix.SYS_LISTMOUNT, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&mountIDs[0])), uintptr(len(mountIDs)), 0, 0, 0)

	if nr, err := listnsSyscallNr(); err == nil {
		var nsIDs [8]uint64
		_, _, _ = syscall.RawSyscall6(nr, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&nsIDs[0])), uintptr(len(nsIDs)), 0, 0, 0)
	}
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
