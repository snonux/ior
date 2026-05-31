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
	atFDCWDInt := int64(unix.AT_FDCWD)
	atFDCWD := uintptr(atFDCWDInt)

	// Best-effort coverage: these calls are expected to fail on most hosts
	// without CAP_SYS_ADMIN, but still exercise syscall tracing paths.
	// fsopen(fsname, flags) is the entry point of the new mount API: it takes a
	// filesystem TYPE name (e.g. "tmpfs"), NOT a path, in args[0] and the
	// FSOPEN_CLOEXEC flag in args[1], returning a new filesystem-context fd. We
	// close the returned fd when the call succeeds so we do not leak it.
	if fd, _, errno := syscall.RawSyscall(unix.SYS_FSOPEN, uintptr(unsafe.Pointer(tmpfs)), uintptr(unix.FSOPEN_CLOEXEC), 0); errno == 0 {
		_ = syscall.Close(int(fd))
	}
	_, _, _ = syscall.RawSyscall6(unix.SYS_MOUNT, uintptr(unsafe.Pointer(none)), uintptr(unsafe.Pointer(mountPath)), uintptr(unsafe.Pointer(tmpfs)), 0, 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_UMOUNT2, uintptr(unsafe.Pointer(mountPath)), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_UMOUNT2, uintptr(unsafe.Pointer(mountPath)), uintptr(unix.MNT_DETACH), 0)
	_, _, _ = syscall.RawSyscall6(unix.SYS_MOVE_MOUNT, atFDCWD, uintptr(unsafe.Pointer(mountPath)), atFDCWD, uintptr(unsafe.Pointer(mountPath)), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_FSMOUNT, ^uintptr(0), 0, 0)
	_, _, _ = syscall.RawSyscall(unix.SYS_PIVOT_ROOT, uintptr(unsafe.Pointer(newRoot)), uintptr(unsafe.Pointer(putOld)), 0)
	_, _, _ = syscall.RawSyscall6(unix.SYS_QUOTACTL, 0, uintptr(unsafe.Pointer(mountPath)), 0, 0, 0, 0)
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
