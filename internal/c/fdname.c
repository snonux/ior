//+build ignore

// Name of the file a close releases (included by ior.bpf.c after
// fileident.c, whose walk it shares; task xz2).
//
// Userspace names a descriptor from the calls it traced (the fd table) or
// from /proc/<pid>/fd. A descriptor that was opened before the trace began,
// or by a call outside the trace set, has no table entry, and for its close
// procfs is of no use: the event loop gets to the row after the kernel
// released the descriptor (internal/eventloop_procfs_close.go, task jr2). The
// only place that still sees the file is the sys_enter_close program, which
// runs before the close takes effect. So that handler says what the file is
// called.
//
// What is captured is the dentry's own name - the last path component,
// "foo.log" of /var/log/foo.log - and nothing above it:
//   - bpf_d_path is not available to tracepoint programs;
//   - every further component costs a load of d_parent and another copy
//     of a name, a walk to the root needs a loop bound, and would still end at
//     the root of the file's own filesystem, not of the mount tree, i.e.
//     yield a path that looks absolute and is not.
// A last component is honest about being one: userspace shows it as
// "*/foo.log" (file.NewFdLeaf).
//
// Not captured, two kinds of dentry; their closes are the plain fd_event
// they always were and stay unnamed ("E:ino:<n>"):
//   - one that is its own parent. That is the root directory of a
//     filesystem, whose name "/" says nothing about where it is mounted, and
//     every file without a directory: pipes and sockets (empty name), the
//     anonymous-inode files ("[eventfd]", "[eventpoll]", ...) and memfds;
//   - the root of the mount the file was opened through
//     (file->f_path.mnt->mnt_root). Its d_name is what the dentry is called
//     in the filesystem it comes from, not what the process opened: the "/"
//     of a btrfs subvolume mounted as the root filesystem is the subvolume's
//     name ("root"), a bind-mounted directory or single file (a container
//     volume, a Kubernetes subPath) has the name of its source. The name
//     the process used belongs to the mount point's dentry in the parent
//     mount, which is not reachable from the file without the mount tree
//     (struct mount is private to fs/). A file below a bind-mounted
//     directory is not a mount root and has its own last component, which
//     is the one the process used.
//
// Why every close of a named file, tracked or not: the kernel program does
// not know which descriptors userspace can name. A map of "tracked"
// descriptors was rejected for the identity already (one hash helper call
// costs more than the walk), and the file itself does not say when it was
// opened. close is far rarer than read and write, which pay nothing for
// this.
//
// Why a wider enter record and not a second record behind the enter: a
// second reserve and submit, with the walk done once more for it, cost +477
// instructions per close (open+close of one file 300000 times, pinned, perf
// stat -e instructions:k, no ring-buffer drops, medians of six interleaved
// runs: walk +117, reserve and submit +200, string read +110..160). The
// wide record shares the identity walk, which every close pays anyway, and
// is the one reserve the handler does: +146 instructions per close of a
// named file and +21 to +28 per close of any other (dup+close 300000 times,
// same method; AGENTS.md "Name of a closed file").
//
// The capture is part of the file-identity capture: it needs the same walk
// and therefore the same kfunc, and IOR_FILE_IDENT switches both. A kernel
// without the kfunc, an object built before this file, and a run with
// IOR_FILE_IDENT=0 send no such record, and userspace then leaves those rows
// unnamed as before. The record has an event type of its own, so unlike the
// identity word it needs no capability flag: a record that is not sent is
// not read.
//
// The name is copied with bpf_probe_read_kernel, d_name.len bytes of it (at
// most what the record holds), and terminated by the handler. Not
// bpf_probe_read_kernel_str: its byte-wise copy cost 115 instructions more
// per close for a 15-byte name (same measurement: +261 against +146). The
// price is that length and pointer are two loads of a pair a rename on
// another CPU swaps under its seqlock, which a tracepoint program does not
// take. Both loads are of valid memory either way (an old external name is
// freed by RCU, and a non-sleepable program runs inside an RCU read-side
// section), so a close racing a rename of its own file reports, at worst:
//   - the new name read with the old length: when that is longer, the name's
//     own NUL comes first and userspace stops there; when it is shorter, a
//     prefix of the new name;
//   - the old name read with the new length: the same two outcomes;
//   - nothing, when a read that ran past a short name's allocation faulted.
// One more outcome for a short name, which lives inline in the dentry and is
// overwritten in place by a rename: a copy that runs while the bytes are
// being replaced can hold some of the old name and some of the new. So the
// text of such a row is not always a name the file had, or a prefix of one;
// it is wrong for that one row. What does hold in every case: the copy
// never runs past the record's name field, the record's name is terminated
// inside that field, and nothing outside the bytes the kernel let the
// program read reaches user space.

// ior_file_leaf_dentry returns the dentry file was opened through when it has
// a name worth reporting, or NULL: no file, no dentry, a dentry that is its
// own parent, or the root of the file's mount (see above for both). A file
// without a mount does not exist in the kernel; the test for one is there so
// that the comparison never reads through a null pointer, and such a file
// is judged by its parent alone.
static __always_inline struct dentry *ior_file_leaf_dentry(struct file *file) {
    struct dentry *dentry;
    struct vfsmount *mnt;

    if (!file)
        return 0;
    dentry = file->f_path.dentry;
    if (!dentry)
        return 0;
    if (dentry->d_parent == dentry)
        return 0;
    mnt = file->f_path.mnt;
    if (mnt && mnt->mnt_root == dentry)
        return 0;
    return dentry;
}

// ior_copy_leaf_name writes name_len and name of ev from dentry's own name.
//
// name_len is the component's real length (d_name.len), or 0 when the name
// could not be read; userspace takes 0 for "no name" and a length the field
// cannot hold for a cut name. name is always terminated: behind the bytes
// that were copied, or at its first byte when none were. The bytes behind
// the terminator stay stale (see "String fields in ring-buffer records" in
// filter.c).
static __always_inline void ior_copy_leaf_name(struct fd_name_event *ev, struct dentry *dentry) {
    __u32 len;

    len = dentry->d_name.len;
    ev->name_len = len;
    // The bound is what the verifier needs for a variable-length read into
    // the record, and it leaves room for the terminator.
    if (len > IOR_FD_NAME_LENGTH - 1)
        len = IOR_FD_NAME_LENGTH - 1;
    if (bpf_probe_read_kernel(ev->name, len, dentry->d_name.name) < 0) {
        ev->name_len = 0;
        len = 0;
    }
    ev->name[len] = '\0';
}

// ior_emit_fd_name_enter is the enter handler of a single-descriptor syscall
// that names the file behind its descriptor (close; the generated handler
// calls it after its enter hook, with the hook's clock read as now). It
// always stores the file's identity in *file_ident - what ior_file_ident
// returns - and reports whether it sent the enter record:
//   - 1: the file has a last path component; an fd_name_event went out (or
//     the ring buffer had no room for it, which is counted like every other
//     drop). The caller returns.
//   - 0: there is no name to send. The caller sends its plain fd_event, with
//     *file_ident, so the walk is not done twice.
//
// The name fields are ior_copy_leaf_name's.
static __always_inline int ior_emit_fd_name_enter(__u32 pid, __u32 tid, __u32 enter_trace_id, __u64 now, __s32 fd,
                                                  __u32 *file_ident) {
    struct task_struct *task;
    struct file *file;
    struct inode *inode;
    struct dentry *dentry;
    struct fd_name_event *ev;

    *file_ident = 0;
    if (!IOR_FILE_IDENT || !ior_file_ident_supported())
        return 0;
    task = bpf_get_current_task_btf();
    file = ior_file_of_table(task->files, fd);
    if (!file)
        return 0;
    inode = file->f_inode;
    if (inode)
        *file_ident = (__u32)inode->i_ino;
    dentry = ior_file_leaf_dentry(file);
    if (!dentry)
        return 0;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_name_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return 1;
    }

    ev->event_type = ENTER_FD_NAME_EVENT;
    ev->trace_id = enter_trace_id;
    ev->time = now;
    ev->pid = pid;
    ev->tid = tid;
    ev->fd = fd;
    ev->file_ident = *file_ident;
    ior_copy_leaf_name(ev, dentry);

    bpf_ringbuf_submit(ev, 0);
    return 1;
}
