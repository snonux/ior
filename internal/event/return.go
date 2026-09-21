package event

const maxErrno = int64(4095)

// IsErrnoRet reports whether ret is a Linux syscall error return. The kernel
// reserves only -MAX_ERRNO through -1 for errno values; other negative raw
// words can be successful returns from pointer- or offset-valued syscalls.
func IsErrnoRet(ret int64) bool {
	return ret >= -maxErrno && ret < 0
}
