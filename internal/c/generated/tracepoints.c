// Code generated - don't change manually!

#define SYS_EXIT_CACHESTAT 520
#define SYS_ENTER_CACHESTAT 521
#define SYS_EXIT_CLOSE_RANGE 692
#define SYS_ENTER_CLOSE_RANGE 693
#define SYS_EXIT_CLOSE 694
#define SYS_ENTER_CLOSE 695
#define SYS_EXIT_FCHOWN 704
#define SYS_ENTER_FCHOWN 705
#define SYS_EXIT_FCHMOD 718
#define SYS_ENTER_FCHMOD 719
#define SYS_EXIT_FCHDIR 722
#define SYS_ENTER_FCHDIR 723
#define SYS_EXIT_FTRUNCATE 734
#define SYS_ENTER_FTRUNCATE 735
#define SYS_EXIT_COPY_FILE_RANGE 738
#define SYS_ENTER_COPY_FILE_RANGE 739
#define SYS_EXIT_PWRITE64 754
#define SYS_ENTER_PWRITE64 755
#define SYS_EXIT_PREAD64 756
#define SYS_ENTER_PREAD64 757
#define SYS_EXIT_WRITE 758
#define SYS_ENTER_WRITE 759
#define SYS_EXIT_READ 760
#define SYS_ENTER_READ 761
#define SYS_EXIT_LSEEK 762
#define SYS_ENTER_LSEEK 763
#define SYS_EXIT_NEWFSTAT 770
#define SYS_ENTER_NEWFSTAT 771
#define SYS_EXIT_FCNTL 814
#define SYS_ENTER_FCNTL 815
#define SYS_EXIT_IOCTL 816
#define SYS_ENTER_IOCTL 817
#define SYS_EXIT_GETDENTS64 818
#define SYS_ENTER_GETDENTS64 819
#define SYS_EXIT_GETDENTS 820
#define SYS_ENTER_GETDENTS 821
#define SYS_EXIT_SYNC_FILE_RANGE 914
#define SYS_ENTER_SYNC_FILE_RANGE 915
#define SYS_EXIT_FDATASYNC 916
#define SYS_ENTER_FDATASYNC 917
#define SYS_EXIT_FSYNC 918
#define SYS_ENTER_FSYNC 919
#define SYS_EXIT_FSTATFS 936
#define SYS_ENTER_FSTATFS 937
#define SYS_EXIT_FLOCK 1012
#define SYS_ENTER_FLOCK 1013
#define SYS_EXIT_QUOTACTL_FD 1043
#define SYS_ENTER_QUOTACTL_FD 1044
#define SYS_EXIT_IO_URING_REGISTER 1366
#define SYS_ENTER_IO_URING_REGISTER 1367
#define SYS_EXIT_IO_URING_ENTER 1370
#define SYS_ENTER_IO_URING_ENTER 1371

SEC("tracepoint/syscalls/sys_exit_cachestat")
int handle_sys_exit_cachestat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_CACHESTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_cachestat")
int handle_sys_enter_cachestat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_CACHESTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close_range")
int handle_sys_exit_close_range(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_CLOSE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int handle_sys_enter_close_range(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_CLOSE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int handle_sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_CLOSE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_CLOSE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int handle_sys_exit_fchown(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FCHOWN;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int handle_sys_enter_fchown(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FCHOWN;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int handle_sys_exit_fchmod(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FCHMOD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int handle_sys_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FCHMOD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int handle_sys_exit_fchdir(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FCHDIR;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int handle_sys_enter_fchdir(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FCHDIR;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ftruncate")
int handle_sys_exit_ftruncate(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FTRUNCATE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int handle_sys_enter_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FTRUNCATE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_copy_file_range")
int handle_sys_exit_copy_file_range(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_COPY_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int handle_sys_enter_copy_file_range(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_COPY_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int handle_sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_PWRITE64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int handle_sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_PWRITE64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")
int handle_sys_exit_pread64(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_PREAD64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int handle_sys_enter_pread64(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_PREAD64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_WRITE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_WRITE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_READ;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_READ;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lseek")
int handle_sys_exit_lseek(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_LSEEK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int handle_sys_enter_lseek(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_LSEEK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstat")
int handle_sys_exit_newfstat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_NEWFSTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int handle_sys_enter_newfstat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_NEWFSTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int handle_sys_exit_fcntl(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FCNTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int handle_sys_enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FCNTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int handle_sys_exit_ioctl(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_IOCTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_sys_enter_ioctl(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_IOCTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_sys_exit_getdents64(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_GETDENTS64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_sys_enter_getdents64(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_GETDENTS64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents")
int handle_sys_exit_getdents(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_GETDENTS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int handle_sys_enter_getdents(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_GETDENTS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sync_file_range")
int handle_sys_exit_sync_file_range(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_SYNC_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int handle_sys_enter_sync_file_range(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_SYNC_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int handle_sys_exit_fdatasync(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FDATASYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int handle_sys_enter_fdatasync(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FDATASYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsync")
int handle_sys_exit_fsync(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FSYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int handle_sys_enter_fsync(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FSYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fstatfs")
int handle_sys_exit_fstatfs(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FSTATFS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fstatfs")
int handle_sys_enter_fstatfs(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FSTATFS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_flock")
int handle_sys_exit_flock(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_FLOCK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int handle_sys_enter_flock(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_FLOCK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_quotactl_fd")
int handle_sys_exit_quotactl_fd(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_QUOTACTL_FD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl_fd")
int handle_sys_enter_quotactl_fd(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_QUOTACTL_FD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_io_uring_register")
int handle_sys_exit_io_uring_register(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_IO_URING_REGISTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int handle_sys_enter_io_uring_register(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_IO_URING_REGISTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_io_uring_enter")
int handle_sys_exit_io_uring_enter(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_IO_URING_ENTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int handle_sys_enter_io_uring_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_IO_URING_ENTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}


