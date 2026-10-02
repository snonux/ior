//+build ignore

// File identity of a descriptor (included by ior.bpf.c ahead of the generated
// handlers; task 603).
//
// A record that names a file by descriptor number says nothing about which
// file that was: userspace looks the number up in the fd table it built from
// the traced calls, or in /proc/<pid>/fd, and both can describe another file.
// The table goes stale when the number is rebound by something the trace does
// not see (io_uring's IORING_OP_CLOSE/OPENAT, an untraced or lost call), and
// procfs is read when the event loop reaches the row, after a possible
// close and reuse of the number. So the handlers that carry one descriptor
// also say which file it is, and userspace compares (internal/
// eventloop_fileident.go).
//
// The identity is the low 32 bits of the file's inode number:
//   - it is the number /proc/<pid>/fdinfo/<fd> prints as "ino:", which is
//     what validates a procfs answer without touching the file's filesystem
//     (fdinfo has no device, and stat's st_dev is not the superblock's s_dev
//     on btrfs and overlayfs anyway);
//   - it is the same for every descriptor of the file and for as long as the
//     file exists. The struct file pointer is neither comparable with procfs
//     nor a safe key: the slab hands a freed struct file's address to the
//     next open, which is exactly the close-and-reuse case;
//   - 32 bits fit the tail of fd_event and ret_event that was padding, so
//     the hot records keep their size. 0 means "unknown" (also for the rare
//     inode whose low word is 0); userspace then behaves as it did before.
// Not told apart, so userspace may only ever use the identity to refuse a
// name, never to accept one that some other rule would refuse:
//   - the files that share one anonymous inode (eventfd, epoll, io_uring,
//     timerfd, ... - but not pipes and sockets, which have their own);
//   - a file that was given the inode number of one unlinked and freed
//     before it (ext4 and xfs reuse a freed number at once);
//   - two files with the same inode number on different filesystems (every
//     tmpfs counts from the same start), or in different subvolumes or
//     snapshots of one btrfs filesystem (a snapshot keeps the numbers; i_ino
//     is unique per subvolume only);
//   - two inode numbers that differ only above bit 31.
//
// Cost. The walk is current->files->fdt->fd[fd]->f_inode->i_ino. Done with
// bpf_probe_read_kernel it is seven helper calls of about 90 instructions
// each: +645 instructions on every read and write, half of what a traced
// syscall costs in total (measured: a pinned bs=1 dd, perf stat -e
// instructions:k, no ring-buffer drops). A tracepoint program can do better
// since Linux 6.2: bpf_get_current_task_btf() returns a BTF-typed task whose
// pointer fields load directly (an exception-table fixup instead of a helper
// call), and the bpf_rdonly_cast kfunc - the verifier replaces it by a
// register move - types the one pointer a field load cannot: the fd slot,
// which sits behind a `struct file **`. There is one cast; the file pointer
// loaded from the cast slot is typed by that load, and so is everything
// after it. That version has no helper call but the first and costs +78
// instructions (+6%).
//
// Only that version is compiled in. On a kernel without the kfunc (mainline
// before 6.2 and RHEL 8; RHEL 9 rebases its BPF subsystem and may have it,
// which is unverified) the ksym is unresolved, libbpf turns the test below
// into a constant and the call into a poisoned instruction in a branch the
// verifier never follows, and every identity is 0. Userspace does not even
// ask such a kernel: it looks the kfunc up in the kernel's BTF and leaves
// IOR_FILE_IDENT at 0 where it is missing (internal/bpfsetup_kfunc.go), so
// that branch is the second line of defence. The probe-read walk was not
// kept as a fallback: at its cost it would have to be opt-in, and nothing
// here could test it on such a kernel.
//
// Verified by loading on Linux 7.2 only; with the kfunc declared under a name
// the kernel lacks the same object loads and reports 0. A kernel that has the
// kfunc but is not 7.2 therefore runs the walk through a verifier it was
// never loaded on (typed loads from bpf_get_current_task_btf and the kfunc
// in a tracepoint program are both younger than the rest of these programs);
// the safety net for that is userspace's second load without the capture
// when the first is refused (loadWithIdentFallback in
// internal/ior_bpfsetup.go).
//
// The fd slot is typed by borrowing struct kiocb, whose first member is a
// struct file pointer: the kfunc needs the BTF id of a kernel struct, and the
// table's element type is a bare pointer. Should ki_filp ever move off offset
// 0 the load would read the wrong slot, so the capture checks the offset and
// switches itself off.
//
// The walk runs in the context of the task whose table it reads, inside the
// RCU read-side section every non-sleepable program runs in, and all loads
// are fault-safe, so a table being resized or a file being freed by another
// thread costs at worst a wrong or zero identity for that one record.

// The kfunc is declared weak so the object still loads where the kernel does
// not have it (see above).
extern void *bpf_rdonly_cast(const void *obj__ign, __u32 btf_id__k) __ksym __weak;

// ior_file_ident_supported reports whether this kernel can run the walk. All
// three terms are constants once libbpf has relocated the object, so on a
// kernel that cannot, the verifier prunes the walk as dead code.
static __always_inline int ior_file_ident_supported(void) {
    return bpf_ksym_exists(bpf_rdonly_cast) && bpf_core_type_id_kernel(struct kiocb) != 0 &&
           bpf_core_field_offset(struct kiocb, ki_filp) == 0;
}

// ior_file_ident_of_table returns the identity of the file at descriptor fd
// of the table files, or 0 when there is none to report: no table (a kernel
// thread, a task past exit_files), a number outside the table, an empty slot,
// or an inode whose low word is 0. The bounds check against max_fds comes
// before the slot is touched: the slot of a number past the table is some
// other object's memory.
static __always_inline __u32 ior_file_ident_of_table(struct files_struct *files, __s32 fd) {
    struct fdtable *fdt;
    struct file **fds;
    struct kiocb *slot;
    struct file *file;
    struct inode *inode;

    if (!files)
        return 0;
    fdt = files->fdt;
    if (!fdt)
        return 0;
    if (fd < 0 || (__u32)fd >= fdt->max_fds)
        return 0;
    fds = fdt->fd;
    if (!fds)
        return 0;
    slot = bpf_rdonly_cast(fds + fd, bpf_core_type_id_kernel(struct kiocb));
    file = slot->ki_filp;
    if (!file)
        return 0;
    inode = file->f_inode;
    if (!inode)
        return 0;
    return (__u32)inode->i_ino;
}

// ior_file_ident returns the identity of the file the current task has at
// descriptor fd, or 0 (unknown). IOR_FILE_IDENT is written by userspace
// before the load (flags.h); it is tested first, so a run that switched the
// capture off loads no part of the walk.
static __always_inline __u32 ior_file_ident(__s32 fd) {
    struct task_struct *task;

    if (!IOR_FILE_IDENT || !ior_file_ident_supported())
        return 0;
    task = bpf_get_current_task_btf();
    return ior_file_ident_of_table(task->files, fd);
}

// ior_file_ident_of_ret is ior_file_ident for a syscall return value that is
// a new descriptor when it is not an error (the exits of the open kinds): the
// identity of the file the call just installed.
static __always_inline __u32 ior_file_ident_of_ret(__s64 ret) {
    if (ret < 0 || ret > 0x7fffffff)
        return 0;
    return ior_file_ident((__s32)ret);
}
