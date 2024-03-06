// Code generated - don't change manually!

#define SYS_EXIT_CACHESTAT 527
#define SYS_ENTER_CACHESTAT 528
#define SYS_EXIT_CLOSE_RANGE 700
#define SYS_ENTER_CLOSE_RANGE 701
#define SYS_EXIT_CLOSE 702
#define SYS_ENTER_CLOSE 703
#define SYS_EXIT_FCHOWN 712
#define SYS_ENTER_FCHOWN 713
#define SYS_EXIT_FCHMOD 726
#define SYS_ENTER_FCHMOD 727
#define SYS_EXIT_FCHDIR 730
#define SYS_ENTER_FCHDIR 731
#define SYS_EXIT_FTRUNCATE 742
#define SYS_ENTER_FTRUNCATE 743
#define SYS_EXIT_COPY_FILE_RANGE 746
#define SYS_ENTER_COPY_FILE_RANGE 747
#define SYS_EXIT_PWRITE64 762
#define SYS_ENTER_PWRITE64 763
#define SYS_EXIT_PREAD64 764
#define SYS_ENTER_PREAD64 765
#define SYS_EXIT_WRITE 766
#define SYS_ENTER_WRITE 767
#define SYS_EXIT_READ 768
#define SYS_ENTER_READ 769
#define SYS_EXIT_LSEEK 770
#define SYS_ENTER_LSEEK 771
#define SYS_EXIT_NEWFSTAT 778
#define SYS_ENTER_NEWFSTAT 779
#define SYS_EXIT_RENAME 794
#define SYS_ENTER_RENAME 795
#define SYS_EXIT_RENAMEAT 796
#define SYS_ENTER_RENAMEAT 797
#define SYS_EXIT_RENAMEAT2 798
#define SYS_ENTER_RENAMEAT2 799
#define SYS_EXIT_LINK 800
#define SYS_ENTER_LINK 801
#define SYS_EXIT_LINKAT 802
#define SYS_ENTER_LINKAT 803
#define SYS_EXIT_SYMLINK 804
#define SYS_ENTER_SYMLINK 805
#define SYS_EXIT_SYMLINKAT 806
#define SYS_ENTER_SYMLINKAT 807
#define SYS_EXIT_FCNTL 822
#define SYS_ENTER_FCNTL 823
#define SYS_EXIT_IOCTL 824
#define SYS_ENTER_IOCTL 825
#define SYS_EXIT_GETDENTS64 826
#define SYS_ENTER_GETDENTS64 827
#define SYS_EXIT_GETDENTS 828
#define SYS_ENTER_GETDENTS 829
#define SYS_EXIT_SYNC_FILE_RANGE 922
#define SYS_ENTER_SYNC_FILE_RANGE 923
#define SYS_EXIT_FDATASYNC 924
#define SYS_ENTER_FDATASYNC 925
#define SYS_EXIT_FSYNC 926
#define SYS_ENTER_FSYNC 927
#define SYS_EXIT_FSTATFS 944
#define SYS_ENTER_FSTATFS 945
#define SYS_EXIT_FLOCK 1020
#define SYS_ENTER_FLOCK 1021
#define SYS_EXIT_QUOTACTL_FD 1051
#define SYS_ENTER_QUOTACTL_FD 1052
#define SYS_EXIT_IO_URING_REGISTER 1377
#define SYS_ENTER_IO_URING_REGISTER 1378
#define SYS_EXIT_IO_URING_ENTER 1381
#define SYS_ENTER_IO_URING_ENTER 1382

SEC("tracepoint/syscalls/sys_exit_cachestat")
int handle_sys_exit_cachestat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_CACHESTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_CACHESTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close_range")
int handle_sys_exit_close_range(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_CLOSE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_CLOSE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int handle_sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_CLOSE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_CLOSE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int handle_sys_exit_fchown(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FCHOWN;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FCHOWN;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int handle_sys_exit_fchmod(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FCHMOD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FCHMOD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int handle_sys_exit_fchdir(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FCHDIR;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FCHDIR;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ftruncate")
int handle_sys_exit_ftruncate(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FTRUNCATE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FTRUNCATE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_copy_file_range")
int handle_sys_exit_copy_file_range(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_COPY_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int handle_sys_enter_copy_file_range(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NULL_EVENT;
    ev->trace_id = SYS_ENTER_COPY_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int handle_sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_PWRITE64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_PWRITE64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")
int handle_sys_exit_pread64(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_PREAD64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_PREAD64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_WRITE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_WRITE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_READ;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_READ;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lseek")
int handle_sys_exit_lseek(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_LSEEK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_LSEEK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstat")
int handle_sys_exit_newfstat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_NEWFSTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_NEWFSTAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int handle_sys_exit_rename(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_RENAME;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int handle_sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct name_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct name_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NAME_EVENT;
    ev->trace_id = SYS_ENTER_RENAME;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[0]);
    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[1]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int handle_sys_exit_renameat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_RENAMEAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct name_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct name_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NAME_EVENT;
    ev->trace_id = SYS_ENTER_RENAMEAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[1]);
    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[3]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int handle_sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_RENAMEAT2;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct name_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct name_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NAME_EVENT;
    ev->trace_id = SYS_ENTER_RENAMEAT2;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[1]);
    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[3]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_link")
int handle_sys_exit_link(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_LINK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int handle_sys_enter_link(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct name_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct name_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NAME_EVENT;
    ev->trace_id = SYS_ENTER_LINK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[0]);
    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[1]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_linkat")
int handle_sys_exit_linkat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_LINKAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int handle_sys_enter_linkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct name_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct name_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NAME_EVENT;
    ev->trace_id = SYS_ENTER_LINKAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[1]);
    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[3]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int handle_sys_exit_symlink(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_SYMLINK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int handle_sys_enter_symlink(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct name_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct name_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NAME_EVENT;
    ev->trace_id = SYS_ENTER_SYMLINK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[0]);
    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[1]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlinkat")
int handle_sys_exit_symlinkat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_SYMLINKAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int handle_sys_enter_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct name_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct name_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NAME_EVENT;
    ev->trace_id = SYS_ENTER_SYMLINKAT;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[0]);
    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[2]);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int handle_sys_exit_fcntl(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FCNTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FCNTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int handle_sys_exit_ioctl(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_IOCTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_IOCTL;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_sys_exit_getdents64(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_GETDENTS64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_GETDENTS64;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents")
int handle_sys_exit_getdents(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_GETDENTS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_GETDENTS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sync_file_range")
int handle_sys_exit_sync_file_range(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_SYNC_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int handle_sys_enter_sync_file_range(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->event_type = ENTER_NULL_EVENT;
    ev->trace_id = SYS_ENTER_SYNC_FILE_RANGE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int handle_sys_exit_fdatasync(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FDATASYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FDATASYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsync")
int handle_sys_exit_fsync(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FSYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FSYNC;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fstatfs")
int handle_sys_exit_fstatfs(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FSTATFS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FSTATFS;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_flock")
int handle_sys_exit_flock(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_FLOCK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_FLOCK;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_quotactl_fd")
int handle_sys_exit_quotactl_fd(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_QUOTACTL_FD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_QUOTACTL_FD;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_io_uring_register")
int handle_sys_exit_io_uring_register(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_IO_URING_REGISTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_IO_URING_REGISTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_io_uring_enter")
int handle_sys_exit_io_uring_enter(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev)
        return 0;

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = SYS_EXIT_IO_URING_ENTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->ret = ctx->ret;

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

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = SYS_ENTER_IO_URING_ENTER;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (__s32)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}


