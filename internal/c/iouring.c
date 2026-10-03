//+build ignore

// Registered-ring capture for io_uring_register (included by ior.bpf.c ahead
// of the generated handlers; task js2).
//
// io_uring_enter(IORING_ENTER_REGISTERED_RING) and io_uring_register with
// IORING_REGISTER_USE_REGISTERED_RING pass an index into the calling THREAD's
// registered-ring table where a descriptor would be. Which ring an index
// stands for is decided by two io_uring_register opcodes, and only by them
// (and by io_uring_setup(IORING_SETUP_REGISTERED_FD_ONLY), whose return value
// userspace already has):
//   - IORING_REGISTER_RING_FDS (20): arg is an array of nr_args struct
//     io_uring_rsrc_update {offset, resv, data}; data is the ring descriptor,
//     offset the wanted index or -1, and the kernel writes the index it
//     allocated back into offset (io_ringfd_register, io_uring/tctx.c);
//   - IORING_UNREGISTER_RING_FDS (21): the same array with offset the index
//     to release and data 0 (io_ringfd_unregister).
// Both return the number of leading entries they processed, at most
// IO_RINGFD_REG_MAX (16) because a larger nr_args is refused with -EINVAL, or
// an error when the first entry already failed.
//
// The records of the call carry the opcode and nothing of the array, so the
// mapping has to be read here. It is read at sys_exit, for both opcodes:
// that is after the kernel wrote the allocated indexes back, and only there
// is it known how many entries count (ret). The enter handler parks the array
// pointer and the opcode on the tid's enter state (ior_stash_ring_fds), the
// exit handler takes them back with its one lookup of that state and
// publishes the first ret entries as a RING_FDS_EVENT control record
// (ior_emit_ring_fds). Userspace keeps a table per thread from these records
// and names the rows that pass an index after the ring behind it
// (internal/eventloop_ringfds.go).
//
// The record is published whether or not the sampling decision emits the
// call's own enter and exit records. It is state every later row of the
// thread is read by, not a row: a registration that fell to a sampling rate
// would leave userspace with the index's PREVIOUS ring, and rows named after
// the wrong file rather than after none.
//
// Cost. Only the two opcodes pay: every other io_uring_register adds one
// masked compare at enter (ior_ring_fds_opcode) and a zero test at exit, and
// its exit hook takes the two slots from the lookup it does anyway. No other
// syscall's handler changes, io_uring_enter's included.

// The leading "opcode" argument of io_uring_register may carry
// IORING_REGISTER_USE_REGISTERED_RING in its top bit (the fd argument is then
// itself a registered-ring index); the opcode is what is left.
#define IOR_REGISTER_USE_REGISTERED_RING (1U << 31)

// ior_ring_fds_opcode returns the io_uring_register opcode when it is one of
// the two that change the registered-ring table, and 0 for every other.
static __always_inline __u32 ior_ring_fds_opcode(__u64 opcode_arg) {
    __u32 opcode = (__u32)opcode_arg & ~IOR_REGISTER_USE_REGISTERED_RING;

    if (opcode == IOR_REGISTER_RING_FDS || opcode == IOR_UNREGISTER_RING_FDS)
        return opcode;
    return 0;
}

// ior_stash_ring_fds parks the array pointer and the opcode of a ring-fds
// io_uring_register on this tid's enter state: the pointer in the first
// pending slot, the opcode in the second (the call captures no pathname, so
// both are free). The generated enter handler calls it right after
// ior_on_syscall_enter, with that hook's verdict.
//
// The enter state it needs is not always there. ior_on_syscall_enter writes
// none at rate 1 (task 2s2), which is what keeps every OTHER io_uring_register
// off the map; for these two opcodes the entry is written here instead, as
// ior_on_syscall_enter_stateful would have written it (emit_event 1: at rate
// 1 the call is emitted). An entry is taken for this call's only when it
// carries this handler's clock read: an older one of the same syscall belongs
// to a call whose exit never ran.
//
// At any other rate the hook wrote the entry, emitted or not, and the stash
// goes onto it. When it could not (a full map) and the enter is not emitted,
// nothing is written: the hook already counted the invocation, and an entry
// made here would have the exit count it again.
static __always_inline void ior_stash_ring_fds(__u32 tid, __u32 enter_trace_id, __u64 now, int emits,
                                               __u64 opcode_arg, __u64 arg) {
    struct syscall_enter_state fresh = {};
    struct syscall_enter_state *state;
    __u32 opcode = ior_ring_fds_opcode(opcode_arg);

    if (!opcode)
        return;

    state = bpf_map_lookup_elem(&syscall_enter_state_map, &tid);
    if (state && state->enter_trace_id == enter_trace_id && state->start_ns == now) {
        state->pending_filename = arg;
        state->pending_filename2 = opcode;
        return;
    }
    if (!emits)
        return;

    fresh.start_ns = now;
    fresh.enter_trace_id = enter_trace_id;
    fresh.emit_event = 1;
    fresh.pending_filename = arg;
    fresh.pending_filename2 = opcode;
    bpf_map_update_elem(&syscall_enter_state_map, &tid, &fresh, BPF_ANY);
}

// ior_read_ring_fds copies the first ret entries of the io_uring_rsrc_update
// array at arg into updates (IOR_RING_FDS_BYTES bytes, zero-filled first so
// the bytes past the entries are zeros and never stale ring-buffer memory),
// sets *count and returns the RING_FDS_* status. ret must be positive.
//
// One read of exactly the entries the kernel processed: reading all 16 slots
// would fail as a whole (the helper copies all or nothing) for the usual
// one-entry array that ends where its mapping ends. The length is bounded
// before the read, which is also what the verifier needs for a
// variable-length read into the record; a ret above IO_RINGFD_REG_MAX cannot
// come from these opcodes and is reported instead of read.
static __always_inline __u32 ior_read_ring_fds(__u64 arg, __s64 ret, __u32 *count, __u8 *updates) {
    __u32 len;

    *count = 0;
    __builtin_memset(updates, 0, IOR_RING_FDS_BYTES);

    if (ret > IOR_RING_FDS_MAX)
        return RING_FDS_TOO_MANY;
    len = (__u32)ret * IOR_RING_FD_UPDATE_SIZE;
    if (len == 0 || len > IOR_RING_FDS_BYTES)
        return RING_FDS_TOO_MANY;
    if (bpf_probe_read_user(updates, len, (void *)arg) < 0)
        return RING_FDS_READ_FAILED;
    *count = (__u32)ret;
    return RING_FDS_OK;
}

// ior_emit_ring_fds publishes what a ring-fds io_uring_register did as a
// RING_FDS_EVENT control record. The generated exit handler calls it right
// after its exit hook, with the two slots the hook took (both 0 for every
// other opcode, and for a call whose enter state is missing) and before the
// hook's verdict is looked at (see the file comment), so the record precedes
// the call's exit record when there is one. now is the handler's single
// clock read, the time that exit record carries too: userspace uses it to
// notice a call whose control record never arrived.
//
// Only a call that processed at least one entry (ret > 0) changed the table.
// A record whose array could not be read is submitted all the same, with its
// status: the table changed in a way userspace now cannot know, and it has to
// forget what it believed about this thread. A record the ring buffer has no
// room for is counted like every other drop.
static __always_inline void ior_emit_ring_fds(__u32 pid, __u32 tid, __u32 enter_trace_id, __u64 now,
                                              __u64 opcode, __u64 arg, __s64 ret) {
    struct ring_fds_event *ev;

    if (!opcode || ret <= 0)
        return;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ring_fds_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return;
    }

    ev->event_type = RING_FDS_EVENT;
    ev->trace_id = enter_trace_id;
    ev->time = now;
    ev->pid = pid;
    ev->tid = tid;
    ev->opcode = (__u32)opcode;
    ev->reserved = 0;
    ev->status = ior_read_ring_fds(arg, ret, &ev->count, ev->updates);

    bpf_ringbuf_submit(ev, 0);
}
