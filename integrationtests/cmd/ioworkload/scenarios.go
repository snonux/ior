package main

import (
	"fmt"
	"os"
)

// scenarios maps scenario names to their execution functions.
var scenarios = map[string]func() error{
	"crash":                       crash,
	"open-basic":                  openBasic,
	"open-creat":                  openCreat,
	"open-by-handle-at":           openByHandleAt,
	"open-enoent":                 openEnoent,
	"open-rdonly-write":           openRdonlyWrite,
	"open-pid-filter":             openPidFilter,
	"readwrite-basic":             readwriteBasic,
	"readwrite-pread":             readwritePread,
	"readwrite-pwrite":            readwritePwrite,
	"readwrite-readv":             readwriteReadv,
	"readwrite-writev":            readwriteWritev,
	"readwrite-wronly-read":       readwriteWronlyRead,
	"readwrite-rdonly-write":      readwriteRdonlyWrite,
	"readwrite-pread-invalid":     readwritePreadInvalid,
	"readwrite-pwrite-invalid":    readwritePwriteInvalid,
	"close-basic":                 closeBasic,
	"close-range":                 closeRange,
	"close-invalid-fd":            closeInvalidFd,
	"close-double-close":          closeDoubleClose,
	"close-range-empty":           closeRangeEmpty,
	"dup-basic":                   dupBasic,
	"dup-dup2":                    dupDup2,
	"dup-dup3":                    dupDup3,
	"dup-invalid-fd":              dupInvalidFd,
	"dup2-same-fd":                dup2SameFd,
	"dup3-invalid-flags":          dup3InvalidFlags,
	"fcntl-dupfd":                 fcntlDupfd,
	"fcntl-setfl":                 fcntlSetfl,
	"fcntl-dupfd-cloexec":         fcntlDupfdCloexec,
	"fcntl-invalid-fd":            fcntlInvalidFd,
	"fcntl-dupfd-max":             fcntlDupfdMax,
	"rename-basic":                renameBasic,
	"rename-renameat":             renameRenameat,
	"rename-renameat2":            renameRenameat2,
	"rename-enoent":               renameEnoent,
	"rename-noreplace":            renameNoreplace,
	"link-basic":                  linkBasic,
	"link-linkat":                 linkLinkat,
	"link-symlinkat":              linkSymlinkat,
	"link-readlinkat":             linkReadlinkat,
	"link-enoent":                 linkEnoent,
	"link-symlink-eexist":         linkSymlinkEexist,
	"link-readlinkat-einval":      linkReadlinkatEinval,
	"unlink-basic":                unlinkBasic,
	"unlink-unlinkat":             unlinkUnlinkat,
	"unlink-rmdir":                unlinkRmdir,
	"unlink-enoent":               unlinkEnoent,
	"unlink-rmdir-notempty":       unlinkRmdirNotempty,
	"unlink-unlinkat-enoent":      unlinkUnlinkatEnoent,
	"dir-basic":                   dirBasic,
	"dir-mkdirat":                 dirMkdirat,
	"dir-chdir":                   dirChdir,
	"dir-getcwd":                  dirGetcwd,
	"dir-getdents":                dirGetdents,
	"dir-mkdir-eexist":            dirMkdirEexist,
	"dir-chdir-enoent":            dirChdirEnoent,
	"dir-getdents-ebadf":          dirGetdentsEbadf,
	"stat-basic":                  statBasic,
	"stat-fstat":                  statFstat,
	"stat-lstat":                  statLstat,
	"stat-newfstatat":             statNewfstatat,
	"stat-statx":                  statStatx,
	"stat-access":                 statAccess,
	"stat-faccessat":              statFaccessat,
	"stat-enoent":                 statEnoent,
	"stat-access-enoent":          statAccessEnoent,
	"stat-fstat-ebadf":            statFstatEbadf,
	"sync-basic":                  syncBasic,
	"sync-fdatasync":              syncFdatasync,
	"sync-sync":                   syncSync,
	"sync-sync-file-range":        syncSyncFileRange,
	"sync-sync-file-range-to-eof": syncSyncFileRangeToEOF,
	"sync-fsync-ebadf":            syncFsyncEbadf,
	"sync-fdatasync-ebadf":        syncFdatasyncEbadf,
	"sync-file-range-ebadf":       syncFileRangeEbadf,
	"mmap-basic":                  mmapBasic,
	"mmap-msync-sync":             mmapMsyncSync,
	"mmap-msync-invalid-flags":    mmapMsyncInvalidFlags,
	"copy-file-range-basic":       copyFileRangeBasic,
	"copy-file-range-bad-dst-fd":  copyFileRangeBadDstFd,
	"truncate-basic":              truncateBasic,
	"truncate-ftruncate":          truncateFtruncate,
	"truncate-enoent":             truncateEnoent,
	"truncate-ftruncate-ebadf":    truncateFtruncateEbadf,
	"iouring-setup":               iouringSetup,
	"iouring-enter":               iouringEnter,
	"iouring-register":            iouringRegister,
	"iouring-enter-ebadf":         iouringEnterEbadf,
	"iouring-register-ebadf":      iouringRegisterEbadf,
}

func makeTempDir(prefix string) (string, func(), error) {
	dir, err := os.MkdirTemp("", fmt.Sprintf("ioworkload-%s-", prefix))
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }
	return dir, cleanup, nil
}

// crash simulates a workload that fails with a non-zero exit code.
// Used to verify the test harness handles workload failures gracefully.
func crash() error {
	return fmt.Errorf("intentional crash for testing")
}
