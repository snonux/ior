//+build ignore

// Receive-side capture helpers for recvmsg (included by ior.bpf.c ahead of the
// generated handlers). recvfrom needs none: its buffer capacity is the plain
// scalar args[2].

// MSG_TRUNC from the socket ABI (include/linux/socket.h). Written out because
// the value is part of the stable syscall interface and vmlinux.h carries no
// macros.
#define IOR_MSG_TRUNC 0x20

// The iovec array of a recvmsg is summed for at most this many entries. Eight
// is the kernel's own on-stack fast path (UIO_FASTIOV) and covers every
// receive loop libnl, systemd and libpcap issue; a caller with more entries
// makes the capacity unknown rather than partially counted, which userspace
// resolves conservatively (see bytesFromRet in internal/eventloop_exit.go).
#define IOR_RECVMSG_MAX_IOV 8

// The kernel's MAX_RW_COUNT (INT_MAX & PAGE_MASK for 4 KiB pages): the most a
// single read-style syscall ever transfers, whatever the iovec lengths say.
#define IOR_MAX_RW_COUNT 0x7ffff000UL

// Only the leading fields of the userspace struct msghdr and struct iovec are
// declared, as fixed-width integers. The 64-bit userspace ABI is stable, so
// local definitions avoid depending on whatever vmlinux.h a build host ships.
struct ior_user_msghdr {
    __u64 msg_name;
    __s32 msg_namelen;
    __u32 pad;
    __u64 msg_iov;
    __u64 msg_iovlen;
};

struct ior_user_iovec {
    __u64 iov_base;
    __u64 iov_len;
};

// ior_recvmsg_capacity sums the iovec lengths of the msghdr at msg_ptr - the
// number of bytes recvmsg can copy at most. It sets *size and *valid only on
// full success; on any failure (NULL or unreadable msghdr/iovec, more than
// IOR_RECVMSG_MAX_IOV entries) both are left untouched, so the caller's
// initial size_valid = 0 keeps meaning "capacity unknown". The kernel does
// not reject an oversized total, it clamps it to MAX_RW_COUNT, so the sum
// here can only overestimate what was copied - harmless, as userspace counts
// min(ret, capacity) and ret is the real length. Each length is clamped to
// MAX_RW_COUNT before adding as belt-and-braces: it keeps the sum provably
// below 2^35 (8 * 2^31) for the verifier and the reader. It cannot change
// any observable result: probing the kernel shows an oversized iovec total
// either succeeds with the kernel clamping it (one iovec of 2^31..2^46) or
// fails with EFAULT (e.g. two of 2^47, four of 2^62, eight of 2^61), so a
// call whose return value is used has iovec lengths below 2^47 and eight of
// them sum below 2^50; the u64 wrap is unreachable there. The constant is
// INT_MAX & PAGE_MASK for 4 KiB pages; on 16 KiB/64 KiB pages the kernel's
// real limit is smaller, so this overestimates, which is tolerated.
static __always_inline void ior_recvmsg_capacity(void *msg_ptr, __u64 *size, __u32 *valid) {
    struct ior_user_msghdr msg = {};
    __u64 total = 0;

    if (!msg_ptr || bpf_probe_read_user(&msg, sizeof(msg), msg_ptr) != 0)
        return;
    if (msg.msg_iovlen > IOR_RECVMSG_MAX_IOV)
        return;
    if (msg.msg_iovlen > 0 && !msg.msg_iov)
        return;

#pragma unroll
    for (__u32 i = 0; i < IOR_RECVMSG_MAX_IOV; i++) {
        struct ior_user_iovec iov = {};

        if (i >= msg.msg_iovlen)
            break;
        if (bpf_probe_read_user(&iov, sizeof(iov),
                                (void *)(msg.msg_iov + i * sizeof(iov))) != 0)
            return;
        total += iov.iov_len > IOR_MAX_RW_COUNT ? IOR_MAX_RW_COUNT : iov.iov_len;
    }
    *size = total;
    *valid = 1;
}
