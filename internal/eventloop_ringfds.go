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
// name the row after that file. The number is shown only while the entry the
// snapshot was taken of - the fd table's, or the procfs cache's - still is
// what ior holds for the number (ringSlot.stillBound).
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
//     whose rows were sampled out or lost too. That sweep runs when the
//     monitor notices the drop, which is while the loop still consumes
//     records reserved BEFORE the loss; one of those would rebuild a table
//     the lost records then changed, so a record no newer than the drop
//     notice is not applied either (handleRingFdsEvent);
//   - a record is published for a call that is no ring-fds call: BPF matched
//     the enter state a ring-fds call left behind when its exit never ran
//     (its exit probe was detached, or the task died in the call and the tid
//     was reused) to a later io_uring_register of another opcode, which at
//     rate 1 neither writes nor clears that state (internal/c/iouring.c), and
//     read an array through the stale pointer. The call's exit row carries
//     the real opcode and the table goes (confirmRingFdsRecord);
//   - BPF could not read the array (RING_FDS_READ_FAILED): the record says
//     so and the thread's table is forgotten;
//   - the enter state the capture travels on could not be written (a full
//     syscall_enter_state_map) for a call whose rows are sampled out: nothing
//     reports it. Not handled;
//   - the io_uring_register probes are detached while the trace runs (the
//     TUI's probe toggle), or were never selected: registrations are not
//     seen. Never selected means an empty mirror and the old label; detached
//     midway clears every table on the loop goroutine once the manager
//     reports the completed detach (ringProbeWatch).
//     Records queued before the gap or captured during attachment cannot
//     rebuild them; only registrations newer than the completed attach can;
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
	// bound is the entry the snapshot was taken of: the fd table's own, or,
	// with cached set, the procfs cache's. The descriptor number still is
	// the ring's while ior holds exactly this entry for it there. nil when
	// the procfs answer was not kept (it describes no one file): nothing
	// then vouches for the number and it is never shown.
	bound file.File
	// cached says that bound is the procfs cache's entry, not the table's.
	cached bool
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
//
// Neither is a record applied that may have been reserved before the newest
// ring-buffer drop the monitor saw (recordMayPredateDrop, as for the command
// names of task lz2). The sweep that drop caused (applyPendingCommRefresh)
// ran, or will run, while the loop is still behind the loss, so this record
// would put back a slot that a lost unregister and re-register changed
// since, and the thread's later rows would name the ring that was there
// before. The thread keeps its index labels until a registration that is
// newer than the drop notice.
func (e *eventLoop) handleRingFdsEvent(ev *types.RingFdsEvent) {
	defer ev.Recycle()
	rings := e.ringState()
	if !ringFdsRecordUsable(ev) || e.recordMayPredateDrop(ev.Time) || e.ringRecordAcrossProbeChange(ev.Time) {
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
// the empty slot. The slot remembers which of ior's entries the answer came
// from - the fd table's, else the procfs cache's - for stillBound.
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
	switch {
	case fds.tracksExactly(int32(fd), pid, known):
		slot.bound = known
	case fds.cachesExactly(int32(fd), pid, fdFile):
		slot.bound, slot.cached = known, true
	}
	return slot
}

// stillBound reports whether the descriptor number the ring was registered
// from still is the ring's, as far as ior's view of pid's descriptors shows:
// whether the entry the snapshot was taken of is still the one held for the
// number.
//
//   - A ring taken from the fd table is the number's while the table holds
//     that very entry.
//   - A ring named from procfs (created before the trace, or by a call the
//     trace did not see) is the number's while the procfs cache holds that
//     very answer. A traced close of the number removes the answer, and so
//     does a traced call that binds the number (set drops the answer its new
//     table entry shadows), a row whose file identity contradicts it, and
//     the cache's own eviction - the last costs the number although nothing
//     happened to it, which is the safe side. Looking only for a table
//     entry instead would keep showing the number of a ring whose descriptor
//     ior saw closed, even after an untraced call handed it to another file.
//   - A ring whose procfs answer was not kept has nothing to vouch for the
//     number.
//
// A number given up is given up for good: closed stays set.
func (s *ringSlot) stillBound(fds *fdTracker, pid uint32) bool {
	if s.closed {
		return false
	}
	fd := s.ring.FD()
	switch {
	case s.bound == nil:
		s.closed = true
	case s.cached:
		s.closed = !fds.cachesExactly(fd, pid, s.bound)
	default:
		s.closed = !fds.tracksExactly(fd, pid, s.bound)
	}
	return !s.closed
}

// cachesExactly reports whether the procfs cache (not the fd table) holds f
// itself - the same pointer - for (pid, fd). Like tracksExactly it does not
// refresh the LRU age: asking must not keep an answer alive.
func (t *fdTracker) cachesExactly(fd int32, pid uint32, f file.File) bool {
	cached, ok := t.procFdCache[t.key(pid, fd)]
	return ok && file.File(cached) == f
}

// resolveRegisteredRing names the row of a call of thread tid of process pid
// that passed the registered-ring index where a descriptor would be, and
// whose exit record carries exitTime.
//
// A slot that was released names only the call that released it, which is
// the one call whose exit record has the releasing record's time; any other
// use of the index finds the slot empty and clears it.
func (e *eventLoop) resolveRegisteredRing(tid, pid uint32, index int32, exitTime uint64) file.File {
	e.applyRingProbeChanges()
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

// confirmRingFdsRecord checks, at the exit of an io_uring_register, the
// thread's table against the call the row shows. The control record of a
// call carries the time of the call's exit record and is handled ahead of
// it, so the table's last record time says whether this call had one.
//
//   - A call that changed the table (opcode 20/21, ret > 0) must have had
//     one. A table whose last record is another call's missed this one's -
//     the ring buffer had no room for it, or the object in use does not emit
//     it - and no longer says what the thread's slots hold.
//   - Any other call must not have had one. A record of its time was read
//     through the enter state of an older ring-fds call whose exit never ran
//     (see the file comment): it describes an array nobody passed to this
//     call, and it was already applied.
//
// Either way the table is dropped. A thread without a table has nothing to
// be wrong about.
func (e *eventLoop) confirmRingFdsRecord(ep *event.Pair, ev *types.FcntlEvent) {
	if e.rings == nil {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		return
	}
	tbl := e.rings.table(ev.Tid, ev.Pid)
	if tbl == nil {
		return
	}
	opcode := ev.Cmd &^ ioringRegisterUseRegisteredRing
	changes := opcode == types.IOR_REGISTER_RING_FDS || opcode == types.IOR_UNREGISTER_RING_FDS
	hadRecord := tbl.recordTime == retEv.Time
	lostRecord := changes && retEv.Ret > 0 && !hadRecord
	if lostRecord || (!changes && hadRecord) {
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
