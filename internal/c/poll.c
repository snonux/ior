//+build ignore

// Timeout capture helper for select (included by ior.bpf.c ahead of the
// generated handlers). The other poll-family timeouts are a plain __s32 of
// milliseconds or a struct timespec and are emitted inline by the generator.

// The largest whole-second count whose nanoseconds still fit an __s64, and the
// nanoseconds left over at that second: 9223372036 s + 854775807 ns == S64_MAX.
#define IOR_TIMEVAL_MAX_SEC 9223372036LL
#define IOR_TIMEVAL_MAX_SEC_REM_NS 854775807LL

// The userspace struct timeval of the 64-bit ABI, declared locally as
// fixed-width integers so the capture does not depend on the vmlinux.h a build
// host ships.
struct ior_timeval {
    __s64 tv_sec;
    __s64 tv_usec;
};

// ior_timeval_timeout_ns converts the timeout of select(2) to nanoseconds the
// way kern_select() interprets it. The kernel does not reject an out-of-range
// tv_usec; it normalises first and fails with -EINVAL only when the result is
// negative:
//
//     sec  = tv_sec + tv_usec / 1000000
//     nsec = (tv_usec % 1000000) * 1000
//
// So {0, 1500000} is a valid 1.5 s sleep, and so are {-1, 2000000} (1 s) and
// {5, -1000000} (4 s), while {5, -1} is invalid (negative nsec).
//
// |tv_usec| is split into whole seconds and a remainder with unsigned
// arithmetic: BPF has no signed division without -mcpu=v4, and C's modulo of a
// negative value is negative. The sign is applied afterwards. tv_sec is
// clamped to +-2^62 first so that adding the carry (at most about 1.8e13 s)
// cannot wrap.
//
// Returns POLL_TIMEOUT_UNKNOWN_NS for an invalid timeout, and for one that
// would overflow __s64 nanoseconds (the kernel sleeps "forever" then; ior does
// not attempt to model the clamp).
static __always_inline __s64 ior_timeval_timeout_ns(const struct ior_timeval *tv) {
    __u64 usec_abs;
    __s64 carry, rem_usec, sec, nsec;

    if (tv->tv_sec < -(1LL << 62) || tv->tv_sec > (1LL << 62))
        return POLL_TIMEOUT_UNKNOWN_NS;

    usec_abs = tv->tv_usec >= 0 ? (__u64)tv->tv_usec : -(__u64)tv->tv_usec;
    carry = (__s64)(usec_abs / 1000000ULL);
    rem_usec = (__s64)(usec_abs % 1000000ULL);

    if (tv->tv_usec >= 0) {
        sec = tv->tv_sec + carry;
        nsec = rem_usec * 1000LL;
    } else if (rem_usec == 0) {
        sec = tv->tv_sec - carry;
        nsec = 0;
    } else {
        return POLL_TIMEOUT_UNKNOWN_NS;
    }

    if (sec < 0 || nsec < 0)
        return POLL_TIMEOUT_UNKNOWN_NS;
    if (sec > IOR_TIMEVAL_MAX_SEC ||
        (sec == IOR_TIMEVAL_MAX_SEC && nsec > IOR_TIMEVAL_MAX_SEC_REM_NS))
        return POLL_TIMEOUT_UNKNOWN_NS;
    return sec * 1000000000LL + nsec;
}
