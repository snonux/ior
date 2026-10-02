//+build ignore

// File-handle capture for name_to_handle_at and open_by_handle_at (included by
// ior.bpf.c ahead of the generated handlers; task k03).
//
// A file handle is the only thing the two syscalls have in common: the first
// returns one for a pathname, the second opens one, possibly much later and in
// another thread or process. Userspace used to guess which pathname an
// open_by_handle_at belonged to from the thread's last name_to_handle_at and a
// look at /proc/<pid>/fd/<fd>, which describes the descriptor number as it is
// when the event loop gets there, not the file the call opened. With the
// handle in both records the pathname is filed under the handle itself and
// looked up by it (internal/eventloop_handle.go).
//
// Two places read a handle from user memory:
//   - sys_enter_open_by_handle_at, from args[1]: the handle is an input, so it
//     is complete at enter and travels in the enter record;
//   - sys_exit_name_to_handle_at, from the args[2] pointer its enter handler
//     parked on the enter state (ior_stash_pending_handle): the handle is an
//     output the kernel only writes during the call, so there is nothing to
//     read at enter. Only a successful call wrote one; a failed one - the
//     EOVERFLOW a caller provokes on purpose to learn the handle size included
//     - updates at most handle_bytes and emits nothing.

// The leading fields of the userspace struct file_handle, as fixed-width
// integers: the layout is syscall ABI, so a local definition avoids depending
// on whatever vmlinux.h a build host ships. f_handle follows the header.
struct ior_user_file_handle {
    __u32 handle_bytes;
    __s32 handle_type;
};

// ior_read_file_handle copies the struct file_handle at handle_ptr into the
// handle fields of a record and returns the handle_status to store with them
// (see the FILE_HANDLE_* values in types.h). f_handle must be
// IOR_MAX_HANDLE_SZ bytes; it is zero-filled first, so whatever the outcome
// the bytes past the handle are zeros.
//
// The header is read first and the bytes second, with the length the header
// gave: reading a fixed IOR_MAX_HANDLE_SZ bytes would fail as a whole (the
// helper copies all or nothing) whenever the caller's buffer is shorter than
// that and ends at the edge of its mapping. The length is checked against
// IOR_MAX_HANDLE_SZ before the read, which is also the bound the verifier
// needs for a variable-length read into the record. A zero length reads
// nothing and is reported as it is; userspace takes it for no handle.
//
// The two reads are not atomic with the kernel's own copy: a caller that
// rewrites the buffer in between could make the record differ from what the
// kernel used. That only misnames that caller's own row.
static __always_inline __u32 ior_read_file_handle(__u64 handle_ptr, __u32 *handle_bytes, __s32 *handle_type,
                                                  __u8 *f_handle) {
    struct ior_user_file_handle head = {};
    __u32 len;

    *handle_bytes = 0;
    *handle_type = 0;
    __builtin_memset(f_handle, 0, IOR_MAX_HANDLE_SZ);

    if (!handle_ptr)
        return FILE_HANDLE_NULL;
    if (bpf_probe_read_user(&head, sizeof(head), (void *)handle_ptr) < 0)
        return FILE_HANDLE_READ_FAILED;

    *handle_bytes = head.handle_bytes;
    *handle_type = head.handle_type;
    len = head.handle_bytes;
    if (len > IOR_MAX_HANDLE_SZ)
        return FILE_HANDLE_TOO_LARGE;
    if (len == 0)
        return FILE_HANDLE_OK;
    if (bpf_probe_read_user(f_handle, len, (void *)(handle_ptr + sizeof(head))) < 0)
        return FILE_HANDLE_READ_FAILED;
    return FILE_HANDLE_OK;
}

// ior_stash_pending_handle parks name_to_handle_at's output handle pointer on
// this tid's in-flight syscall state, for its exit handler to read the handle
// through. It uses the SECOND pending-pointer slot: name_to_handle_at is a
// single-path kind, so its faulted-pathname recovery occupies only the first,
// and reusing the free slot keeps struct syscall_enter_state - zeroed and
// written on every stateful enter - at its size and the exit hook at one
// lookup (the pointer comes back through ior_on_syscall_exit_take_filenames).
// The generated enter handler calls it on every emitted enter, right after
// ior_on_syscall_enter_stateful created the entry.
static __always_inline void ior_stash_pending_handle(__u32 tid, __u64 handle_ptr) {
    ior_stash_pending_filename2(tid, handle_ptr);
}

// ior_emit_file_handle publishes the handle a successful name_to_handle_at
// wrote to handle_ptr as a FILE_HANDLE_EVENT control record. The generated exit
// handler calls it only for ctx->ret == 0 and before it reserves its own exit
// record, so the ring buffer hands userspace the handle while the enter event
// of the call is still pending; now is that handler's single clock read, the
// time its exit record carries too (see struct file_handle_event).
//
// A handle that cannot be read completely, or that is empty, is discarded
// rather than submitted: it identifies nothing, and userspace then simply
// files no name for the call. So is a record the ring buffer has no room for
// (counted like every other drop).
static __always_inline void ior_emit_file_handle(__u32 pid, __u32 tid, __u32 enter_trace_id, __u64 now,
                                                 __u64 handle_ptr) {
    struct file_handle_event *ev;

    if (!handle_ptr)
        return;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct file_handle_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return;
    }

    ev->event_type = FILE_HANDLE_EVENT;
    ev->trace_id = enter_trace_id;
    ev->time = now;
    ev->pid = pid;
    ev->tid = tid;
    ev->reserved = 0;
    ev->handle_status = ior_read_file_handle(handle_ptr, &ev->handle_bytes, &ev->handle_type, ev->f_handle);
    if (ev->handle_status != FILE_HANDLE_OK || ev->handle_bytes == 0) {
        bpf_ringbuf_discard(ev, 0);
        return;
    }

    bpf_ringbuf_submit(ev, 0);
}
