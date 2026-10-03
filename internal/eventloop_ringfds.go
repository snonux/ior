package internal

import (
	"math"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Naming the ring behind a registered-ring index (task js2).
//
// io_uring_enter(IORING_ENTER_REGISTERED_RING) and io_uring_register with
// IORING_REGISTER_USE_REGISTERED_RING pass an index into the calling thread's
// registered-ring table where a descriptor would be (eventloop_iouring.go).
// The table is the kernel's, per thread (struct io_uring_task
// registered_rings[IO_RINGFD_REG_MAX], 16 slots), and three calls write it:
//
//   - io_uring_register(IORING_REGISTER_RING_FDS) puts the ring of a
//     descriptor into a slot, and IORING_UNREGISTER_RING_FDS empties slots.
//     What they did is in a user array the records of the call do not carry,
//     so the BPF exit handler reads it and reports it in a RING_FDS_EVENT
//     control record (internal/c/iouring.c), which handleRingFdsEvent applies;
//   - io_uring_setup(IORING_SETUP_REGISTERED_FD_ONLY) puts a ring that has no
//     descriptor at all into the slot it returns (forgetRegisteredRing).
//
// ringTracker mirrors that table per tid, and a row that passes an index is
// named after the ring its slot holds (resolveRegisteredRing). An index the
// mirror knows nothing of - registered before the trace, by a call whose
// record was lost, from a descriptor ior cannot name - keeps the label it
// always had, "io_uring:reg[<index>]".
//
// What a slot holds is the ring as it was when it was registered, not a
// descriptor number: a SNAPSHOT of the fd table's entry (or of the procfs
// answer) for the descriptor the call named, taken while the control record
// is handled. A registered ring stays usable after close(fd) - the kernel
// table holds its own reference to the file - and the number may then come
// back for any other file, so looking the number up when a row arrives would
// name the row after that file. The number is shown only while the fd table
// still vouches for it (ringSlot.stillBound).
//
// Only an io_uring file is believed. The kernel refuses to register anything
// else (io_ring_add_registered_fd: -EOPNOTSUPP), so a name other than the
// io_uring anonymous inode's says that what ior knows of the descriptor is
// another file than the one registered - a stale table entry, or a procfs
// link read after the number was reused - and the slot stays unknown. The
// file identity (task 603) cannot help beyond that: all io_uring files share
// one anonymous inode, so two rings are told apart by nothing ior has. A
// descriptor that was closed and reused by ANOTHER ring before the control
// record was handled therefore names the slot correctly ("anon_inode:
// [io_uring]") but with a number that is that other ring's.
//
// Lifetime, as the kernel has it:
//   - the table belongs to the thread and is not inherited: a new task starts
//     without one (copy_process sets p->io_uring = NULL), whatever the clone
//     flags. retireRecycledTid drops a tid's table when a task is created
//     under it;
//   - it ends with the thread (do_exit: io_uring_files_cancel ->
//     io_uring_unreg_ringfd): handleProcessExitEvent drops it;
//   - an execve empties it (begin_new_exec: io_uring_task_cancel ->
//     io_uring_unreg_ringfd, then __io_uring_free): handleProcessExecEvent
//     drops the exec'ing thread's, under both tids of a non-leader exec. The
//     other threads of the process die in de_thread and report their exit.
//
// What can leave the mirror wrong, and what is done about each:
//   - the control record is lost to a full ring buffer. The call's own exit
//     record says so when it arrives (confirmRingFdsRecord: no record of that
//     time was applied), and a counted drop forgets every table
//     (applyPendingCommRefresh), because the lost record may belong to a call
//     whose rows were sampled out or lost too;
//   - BPF could not read the array (RING_FDS_READ_FAILED): the record says
//     so and the thread's table is forgotten;
//   - the enter state the capture travels on could not be written (a full
//     syscall_enter_state_map) for a call whose rows are sampled out: nothing
//     reports it. Not handled;
//   - the io_uring_register probes are detached while the trace runs (the
//     TUI's probe toggle), or were never selected: registrations are not
//     seen. Never selected means an empty mirror and the old label; detached
//     midway leaves the tables as they were. Not handled;
//   - -tid traces one thread: another thread's table is not seen, and none
//     of its rows are either.
//
// The record is applied when it arrives and needs no pending enter, unlike
// the handle record of name_to_handle_at: everything it says is in it, and it
// is published for calls whose own records the sampling rate dropped.

// ioUringFileName is what /proc/<pid>/fd shows for every io_uring file, and
// so the name ior has for a ring descriptor (handleIoUringSetupExit).
const ioUringFileName = "anon_inode:[io_uring]"

// defaultMaxRingTables caps the tids ringTracker keeps a table of. A table
// goes with its thread; the cap only bounds what lost exit records leave
// behind on a host that churns io_uring threads.
const defaultMaxRingTables = 4096

// ringSlot is one slot of a thread's registered-ring table. The zero value
// is a slot ior knows nothing of.
type ringSlot struct {
	// ring is the snapshot of the ring's descriptor (see the file comment),
	// nil when the slot is empty or unknown. It is never written again, so
	// the rows of the index share it.
	ring *file.FdFile
	// bound is the fd table's own entry the snapshot was taken of, nil when
	// the descriptor was named from procfs. The descriptor number still is
	// the ring's while the table holds exactly this entry for it.
	bound file.File
	// closed is set for good once the number was seen given up or rebound.
	closed bool
	// releasedAt is the time of the control record that released the slot,
	// 0 while it is registered. The slot is kept until another call uses the
	// index, because the releasing call may itself be addressed by it and
	// its row, which arrives behind the record, is still that ring's.
	releasedAt uint64
}

// ringTable mirrors the registered-ring table of one thread.
type ringTable struct {
	// pid is the process the thread belonged to when the table was made; a
	// record or a row of the tid under another pid meets a recycled number.
	pid uint32
	// recordTime is the time of the last control record applied to the
	// table, which is the time of that call's exit record.
	recordTime uint64
	slots      [types.IOR_RING_FDS_MAX]ringSlot
}

// ringTracker holds the registered-ring tables by tid.
type ringTracker struct {
	tables    map[uint32]*ringTable
	maxTables int
}

func (e *eventLoop) ringState() *ringTracker {
	if e.rings == nil {
		e.rings = &ringTracker{}
	}
	return e.rings
}

func (t *ringTracker) limit() int {
	if t.maxTables > 0 {
		return t.maxTables
	}
	return defaultMaxRingTables
}

// table returns the table of the thread tid of process pid, or nil. A table
// made under another pid is a previous owner's of the number and is dropped.
func (t *ringTracker) table(tid, pid uint32) *ringTable {
	tbl := t.tables[tid]
	if tbl != nil && tbl.pid != pid {
		delete(t.tables, tid)
		return nil
	}
	return tbl
}

// ensureTable is table that makes the table when the thread has none. A
// full map is emptied rather than trimmed by age: it takes that many threads
// whose exit records were lost, and what goes is the name of rings whose rows
// then fall back to their index.
func (t *ringTracker) ensureTable(tid, pid uint32) *ringTable {
	if tbl := t.table(tid, pid); tbl != nil {
		return tbl
	}
	if t.tables == nil {
		t.tables = make(map[uint32]*ringTable)
	}
	if len(t.tables) >= t.limit() {
		clear(t.tables)
	}
	tbl := &ringTable{pid: pid}
	t.tables[tid] = tbl
	return tbl
}

// dropThread forgets the table of tid: the thread is gone, exec'd, or its
// table changed in a way ior does not know.
func (t *ringTracker) dropThread(tid uint32) {
	delete(t.tables, tid)
}

// dropAll forgets every table (a control record may have been lost).
func (t *ringTracker) dropAll() {
	clear(t.tables)
}

// handleRingFdsEvent applies what an io_uring_register did to its thread's
// registered-ring table (see the file comment). Like every control record it
// never becomes a row, and it owns the event it is handed.
//
// A record that does not describe the table change completely - an array
// BPF could not read, an opcode or an index that cannot be - leaves the
// thread's table unknown as a whole: which slots it would have changed is
// exactly what is missing.
func (e *eventLoop) handleRingFdsEvent(ev *types.RingFdsEvent) {
	defer ev.Recycle()
	rings := e.ringState()
	if !ringFdsRecordUsable(ev) {
		rings.dropThread(ev.Tid)
		return
	}
	tbl := rings.ensureTable(ev.Tid, ev.Pid)
	tbl.recordTime = ev.Time
	for i := 0; i < int(ev.Count); i++ {
		update, _ := ev.Update(i)
		slot := &tbl.slots[update.Index]
		if ev.Opcode == types.IOR_UNREGISTER_RING_FDS {
			slot.release(ev.Time)
			continue
		}
		*slot = e.snapshotRing(ev.Pid, update.Fd)
	}
}

// ringFdsRecordUsable reports whether ev describes a table change ior can
// apply: an array that was read, of a ring-fds call, with a count the array
// can hold and indexes inside the table.
func ringFdsRecordUsable(ev *types.RingFdsEvent) bool {
	if ev.TraceId != types.SYS_ENTER_IO_URING_REGISTER || ev.Status != types.RING_FDS_OK {
		return false
	}
	if ev.Opcode != types.IOR_REGISTER_RING_FDS && ev.Opcode != types.IOR_UNREGISTER_RING_FDS {
		return false
	}
	if ev.Count == 0 || ev.Count > types.IOR_RING_FDS_MAX {
		return false
	}
	for i := 0; i < int(ev.Count); i++ {
		if update, _ := ev.Update(i); update.Index >= types.IOR_RING_FDS_MAX {
			return false
		}
	}
	return true
}

// release marks the slot as released by the control record of time at. An
// empty slot stays empty: the kernel accepts releasing one.
func (s *ringSlot) release(at uint64) {
	if s.ring == nil {
		return
	}
	s.releasedAt = at
}

// snapshotRing builds the slot of a ring registered from descriptor fd of
// process pid: what ior knows the descriptor as right now, which is the
// state the call returned in as far as the trace shows (the record is
// handled in stream order). A descriptor ior has no io_uring name for gives
// the empty slot.
func (e *eventLoop) snapshotRing(pid uint32, fd uint64) ringSlot {
	if fd > math.MaxInt32 {
		return ringSlot{}
	}
	fds := e.fdState()
	known := fds.resolve(int32(fd), pid)
	fdFile, ok := known.(*file.FdFile)
	if !ok || fdFile.Name() != ioUringFileName {
		return ringSlot{}
	}
	slot := ringSlot{ring: fdFile.Detach()}
	if fds.tracksExactly(int32(fd), pid, known) {
		slot.bound = known
	}
	return slot
}

// stillBound reports whether the descriptor number the ring was registered
// from still is the ring's, as far as the fd table of pid shows. A ring
// taken from the table is the number's while the table holds that very
// entry; a ring named from procfs was not in the table, so any entry that
// has appeared for the number since is a newer file. A number given up is
// given up for good: closed stays set.
func (s *ringSlot) stillBound(fds *fdTracker, pid uint32) bool {
	if s.closed {
		return false
	}
	fd := s.ring.FD()
	if s.bound != nil {
		s.closed = !fds.tracksExactly(fd, pid, s.bound)
	} else {
		s.closed = fds.tracks(fd, pid)
	}
	return !s.closed
}

// tracks reports whether the fd table (not the procfs cache) holds an entry
// for (pid, fd). Like tracksExactly it does not refresh the LRU age.
func (t *fdTracker) tracks(fd int32, pid uint32) bool {
	_, ok := t.files[t.key(pid, fd)]
	return ok
}

// resolveRegisteredRing names the row of a call of thread tid of process pid
// that passed the registered-ring index where a descriptor would be, and
// whose exit record carries exitTime.
//
// A slot that was released names only the call that released it, which is
// the one call whose exit record has the releasing record's time; any other
// use of the index finds the slot empty and clears it.
func (e *eventLoop) resolveRegisteredRing(tid, pid uint32, index int32, exitTime uint64) file.File {
	if e.rings == nil || index < 0 || index >= types.IOR_RING_FDS_MAX {
		return file.NewRegisteredRing(index)
	}
	tbl := e.rings.table(tid, pid)
	if tbl == nil {
		return file.NewRegisteredRing(index)
	}
	slot := &tbl.slots[index]
	if slot.ring == nil {
		return file.NewRegisteredRing(index)
	}
	if slot.releasedAt != 0 && slot.releasedAt != exitTime {
		*slot = ringSlot{}
		return file.NewRegisteredRing(index)
	}
	return file.NewRegisteredRingOf(index, slot.ring, !slot.stillBound(e.fdState(), pid))
}

// confirmRingFdsRecord checks, at the exit of an io_uring_register, that the
// control record of a call that changed the registered-ring table was
// applied: the record carries the time of this exit record, and is handled
// ahead of it. A table whose last record is another call's missed this
// one's - the ring buffer had no room for it, or the object in use does not
// emit it - and no longer says what the thread's slots hold, so it is
// dropped. A thread without a table has nothing to be wrong about.
func (e *eventLoop) confirmRingFdsRecord(ep *event.Pair, ev *types.FcntlEvent) {
	if e.rings == nil {
		return
	}
	opcode := ev.Cmd &^ ioringRegisterUseRegisteredRing
	if opcode != types.IOR_REGISTER_RING_FDS && opcode != types.IOR_UNREGISTER_RING_FDS {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret <= 0 {
		return
	}
	tbl := e.rings.table(ev.Tid, ev.Pid)
	if tbl != nil && tbl.recordTime != retEv.Time {
		e.rings.dropThread(ev.Tid)
	}
}

// forgetRegisteredRing empties the slot index of thread tid: an
// io_uring_setup(IORING_SETUP_REGISTERED_FD_ONLY) just put a ring without a
// descriptor there, which ior has no name for. The kernel only picks a free
// slot, so anything the mirror holds for it was already wrong.
func (e *eventLoop) forgetRegisteredRing(tid, pid uint32, index int32) {
	if e.rings == nil || index < 0 || index >= types.IOR_RING_FDS_MAX {
		return
	}
	if tbl := e.rings.table(tid, pid); tbl != nil {
		tbl.slots[index] = ringSlot{}
	}
}
