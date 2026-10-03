package internal

import (
	"encoding/binary"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// These tests pin task js2: a row that passes a registered-ring index is
// named after the ring the thread registered under it, as the RING_FDS_EVENT
// control records of its io_uring_register calls report it, and keeps the
// "io_uring:reg[<index>]" label whenever the mirror of the thread's table
// cannot vouch for the slot.

const (
	// Opcodes are spelled out (not the production constants) so a wrong
	// constant in the implementation cannot cancel out against the test.
	ringOpRegister   = 20
	ringOpUnregister = 21
	ringOpProbe      = 8
	// ringCallDuration is how long each fed call takes; the control record
	// and the exit record of a call share the time this much after its enter.
	ringCallDuration = 100
	// secondRingFd is a second ring descriptor of the process.
	secondRingFd = int32(9)
)

// ringFeed drives io_uring records through the loop's raw path as the thread
// (pid, tid), each call at a later time than the one before.
type ringFeed struct {
	t        *testing.T
	el       *eventLoop
	pid, tid uint32
	time     uint64
}

// newRingFeed returns a feed whose process has an ordinary file on fd 0, a
// ring on fd 3 (newIoUringEventLoop) and a second ring on secondRingFd. The
// thread is not the group leader, so that the tid and the pid are different
// numbers wherever the code under test could confuse the two.
func newRingFeed(t *testing.T) *ringFeed {
	t.Helper()
	el := newIoUringEventLoop(t, globalfilter.Filter{})
	el.fdState().set(secondRingFd, execCommPid, file.NewFd(secondRingFd, realRingName, 2))
	return &ringFeed{t: t, el: el, pid: execCommPid, tid: execCommPid + 1, time: ioUringPairStart}
}

// raw feeds one record and returns the pair it completed, if any.
func (f *ringFeed) raw(record []byte) *event.Pair {
	f.t.Helper()
	out := make(chan *event.Pair, 1)
	f.el.processRawEvent(record, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// ringUpdate is one element of a control record's array.
type ringUpdate struct {
	index uint32
	fd    uint64
}

// record builds the control record of a call that exits at exitTime.
func (f *ringFeed) record(exitTime uint64, opcode uint32, updates ...ringUpdate) *types.RingFdsEvent {
	ev := &types.RingFdsEvent{
		EventType: types.RING_FDS_EVENT,
		TraceId:   types.SYS_ENTER_IO_URING_REGISTER,
		Time:      exitTime,
		Pid:       f.pid,
		Tid:       f.tid,
		Opcode:    opcode,
		Status:    1,
		Count:     uint32(len(updates)),
	}
	for i, u := range updates {
		binary.LittleEndian.PutUint32(ev.Updates[i*16:], u.index)
		binary.LittleEndian.PutUint32(ev.Updates[i*16+4:], 0xdead)
		binary.LittleEndian.PutUint64(ev.Updates[i*16+8:], u.fd)
	}
	return ev
}

// call feeds one io_uring call - its enter, the control record when rec is
// not nil (stamped with the exit's time) and its exit - and returns the row.
func (f *ringFeed) call(enter, exit types.TraceId, fd, cmd uint32, ret int64, rec *types.RingFdsEvent) *event.Pair {
	f.t.Helper()
	f.time += 10 * ringCallDuration
	_, enterRaw := makeEnterIoUringEvent(f.t, f.time, f.pid, f.tid, enter, fd, cmd)
	if ep := f.raw(enterRaw); ep != nil {
		f.t.Fatalf("an enter record completed a pair: %v", ep)
	}
	if rec != nil {
		rec.Time = f.time + ringCallDuration
		f.raw(eventBytes(f.t, rec))
	}
	_, exitRaw := makeExitRetEvent(f.t, f.time+ringCallDuration, f.pid, f.tid, exit, ret)
	ep := f.raw(exitRaw)
	if ep == nil {
		f.t.Fatal("unfiltered io_uring pair must be emitted")
	}
	f.t.Cleanup(ep.Recycle)
	return ep
}

// register feeds io_uring_register(ringFd, IORING_REGISTER_RING_FDS) that
// put the ring of ringFd into slot index.
func (f *ringFeed) register(index uint32, ringFd int32) *event.Pair {
	f.t.Helper()
	rec := f.record(0, ringOpRegister, ringUpdate{index, uint64(ringFd)})
	return f.call(types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER, uint32(ringFd), ringOpRegister, 1, rec)
}

// unregisterByIndex feeds the release of slot index by a call that addresses
// the ring through that index.
func (f *ringFeed) unregisterByIndex(index uint32) *event.Pair {
	f.t.Helper()
	rec := f.record(0, ringOpUnregister, ringUpdate{index, 0})
	return f.call(types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER,
		index, ringOpUnregister|registerUseRegistered, 1, rec)
}

// enter feeds io_uring_enter(index, IORING_ENTER_REGISTERED_RING).
func (f *ringFeed) enter(index uint32) *event.Pair {
	f.t.Helper()
	return f.call(types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER, index, enterRegisteredRing, 0, nil)
}

// closeFd feeds a successful close(fd).
func (f *ringFeed) closeFd(fd int32) {
	f.t.Helper()
	f.time += 10 * ringCallDuration
	_, enterRaw := makeEnterFdEvent(f.t, f.time, f.pid, f.tid, fd, types.SYS_ENTER_CLOSE)
	_, exitRaw := makeExitCloseEvent(f.t, f.time+ringCallDuration, f.pid, f.tid, 0)
	f.raw(enterRaw)
	if ep := f.raw(exitRaw); ep != nil {
		ep.Recycle()
	}
}

// wantRing fails unless ep is named after the ring registered from fd under
// index, with that descriptor (-1: the number is no longer the ring's).
func wantRing(t *testing.T, ep *event.Pair, index uint32, fd, shownFd int32) {
	t.Helper()
	if got := ep.File.Name(); got != realRingName {
		t.Errorf("file = %q, want the ring %q", got, realRingName)
	}
	if got := ep.File.FD(); got != shownFd {
		t.Errorf("FD() = %d, want %d", got, shownFd)
	}
	want := string(file.NewRegisteredRingOf(int32(index), file.NewFd(fd, realRingName, 2), shownFd < 0).AppendString(nil, nil))
	if got := ep.File.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// wantIndexLabel fails unless ep carries the index label and no descriptor.
func wantIndexLabel(t *testing.T, ep *event.Pair, index uint32) {
	t.Helper()
	want := file.NewRegisteredRing(int32(index)).Name()
	if got := ep.File.Name(); got != want {
		t.Errorf("file = %q, want the index label %q", got, want)
	}
	if got := ep.File.FD(); got != -1 {
		t.Errorf("FD() = %d, want -1 (an index is not a descriptor)", got)
	}
}

func TestRegisteredRingRowsNameTheRing(t *testing.T) {
	f := newRingFeed(t)
	reg := f.register(0, realRingFd)
	if got := reg.File.Name(); got != realRingName || reg.File.FD() != realRingFd {
		t.Errorf("registration row = %q fd %d, want the ring on its descriptor", got, reg.File.FD())
	}
	wantRing(t, f.enter(0), 0, realRingFd, realRingFd)
	// io_uring_register through the index is named the same way.
	probe := f.call(types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER,
		0, ringOpProbe|registerUseRegistered, 0, nil)
	wantRing(t, probe, 0, realRingFd, realRingFd)
	// A second ring in another slot, registered through the first index.
	rec := f.record(0, ringOpRegister, ringUpdate{5, uint64(secondRingFd)})
	f.call(types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER, 0, ringOpRegister|registerUseRegistered, 1, rec)
	wantRing(t, f.enter(5), 5, secondRingFd, secondRingFd)
	wantRing(t, f.enter(0), 0, realRingFd, realRingFd)
	// The fd table is never changed by any of it.
	assertFdNameTracked(t, f.el, stdinFd, stdinName)
	assertFdNameTracked(t, f.el, realRingFd, realRingName)
}

// A record names what its call did even when the call's own records never
// arrive (sampled out, or shed): it is applied when it arrives.
func TestRingFdsRecordAppliesWithoutItsRows(t *testing.T) {
	f := newRingFeed(t)
	f.raw(eventBytes(t, f.record(f.time+1, ringOpRegister, ringUpdate{2, uint64(realRingFd)})))
	wantRing(t, f.enter(2), 2, realRingFd, realRingFd)
}

// Only the first count elements of a record are entries; what follows them
// in the array is not read, and several entries of one call all apply.
func TestRingFdsRecordAppliesExactlyItsCount(t *testing.T) {
	f := newRingFeed(t)
	rec := f.record(f.time+1, ringOpRegister,
		ringUpdate{4, uint64(realRingFd)}, ringUpdate{5, uint64(secondRingFd)}, ringUpdate{6, uint64(realRingFd)})
	rec.Count = 2
	f.raw(eventBytes(t, rec))
	wantRing(t, f.enter(4), 4, realRingFd, realRingFd)
	wantRing(t, f.enter(5), 5, secondRingFd, secondRingFd)
	wantIndexLabel(t, f.enter(6), 6)
}

// ringLabelCase is one way a slot is not, or no longer, known: after the
// registration of realRingFd under index 0, undo runs and the thread (or the
// one undo switched the feed to) enters through index 0 again.
type ringLabelCase struct {
	name string
	undo func(f *ringFeed)
}

// ringLifetimeCases end the table with its thread, as the kernel does.
func ringLifetimeCases() []ringLabelCase {
	return []ringLabelCase{
		{"another thread of the process", func(f *ringFeed) { f.tid++ }},
		{"the tid under another process", func(f *ringFeed) { f.pid++ }},
		{"the thread exited", func(f *ringFeed) { f.raw(makeThreadExitEvent(f.t, f.time+1, f.pid, f.tid)) }},
		{"a new task got the tid", func(f *ringFeed) {
			f.raw(makeTaskNewtaskEvent(f.t, f.pid, f.tid, "ioworkload", cloneThread))
		}},
		{"the thread exec'd", func(f *ringFeed) { f.raw(makeProcessExecEvent(f.t, f.time+1, f.pid, f.tid, "next")) }},
		{"a non-leader exec left the tid", func(f *ringFeed) {
			f.raw(makeProcessExecEventFrom(f.t, f.time+1, f.pid, f.pid, f.tid, "next"))
		}},
		{"a non-leader exec took the tid over", func(f *ringFeed) {
			f.raw(makeProcessExecEventFrom(f.t, f.time+1, f.pid, f.tid, f.tid+7, "next"))
		}},
	}
}

// ringRecordCases change or invalidate the slot through control records.
func ringRecordCases() []ringLabelCase {
	broken := func(mutate func(rec *types.RingFdsEvent)) func(f *ringFeed) {
		return func(f *ringFeed) {
			rec := f.record(f.time+1, ringOpRegister, ringUpdate{1, uint64(secondRingFd)})
			mutate(rec)
			f.raw(eventBytes(f.t, rec))
		}
	}
	return []ringLabelCase{
		{"the index was released", func(f *ringFeed) {
			f.call(types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER, uint32(realRingFd),
				ringOpUnregister, 1, f.record(0, ringOpUnregister, ringUpdate{0, 0}))
		}},
		{"an array BPF could not read", broken(func(rec *types.RingFdsEvent) { rec.Status, rec.Count = 2, 0 })},
		{"a failed read that still claims an entry", broken(func(rec *types.RingFdsEvent) { rec.Status = 2 })},
		{"a status ior does not know", broken(func(rec *types.RingFdsEvent) { rec.Status = 0 })},
		{"a count the table cannot hold", broken(func(rec *types.RingFdsEvent) { rec.Count = 17 })},
		{"an empty record", broken(func(rec *types.RingFdsEvent) { rec.Count = 0 })},
		{"an index outside the table", broken(func(rec *types.RingFdsEvent) {
			binary.LittleEndian.PutUint32(rec.Updates[0:], 16)
		})},
		{"an opcode that is neither", broken(func(rec *types.RingFdsEvent) { rec.Opcode = ringOpProbe })},
		{"a record of another syscall", broken(func(rec *types.RingFdsEvent) { rec.TraceId = types.SYS_ENTER_IO_URING_ENTER })},
		{"another ring took the index without a descriptor", func(f *ringFeed) {
			f.call(types.SYS_ENTER_IO_URING_SETUP, types.SYS_EXIT_IO_URING_SETUP, 0xffffffff, setupRegisteredFdOnly, 0, nil)
		}},
	}
}

// ringLossCases are the ways a control record goes missing.
func ringLossCases() []ringLabelCase {
	withoutRecord := func(opcode uint32) func(f *ringFeed) {
		return func(f *ringFeed) {
			f.call(types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER, uint32(secondRingFd), opcode, 1, nil)
		}
	}
	return []ringLabelCase{
		{"a registration whose record was lost", withoutRecord(ringOpRegister)},
		{"a release whose record was lost", withoutRecord(ringOpUnregister)},
		{"a lost record, the call through an index", withoutRecord(ringOpRegister | registerUseRegistered)},
		{"a registration answered by another call's record", func(f *ringFeed) {
			rec := f.record(0, ringOpRegister, ringUpdate{1, uint64(secondRingFd)})
			f.raw(eventBytes(f.t, rec))
			withoutRecord(ringOpRegister)(f)
		}},
		{"the ring buffer dropped records", func(f *ringFeed) { f.el.commRefreshPending.Store(true) }},
	}
}

func TestRegisteredRingRowKeepsItsIndexLabel(t *testing.T) {
	var cases []ringLabelCase
	for _, group := range [][]ringLabelCase{ringLifetimeCases(), ringRecordCases(), ringLossCases()} {
		cases = append(cases, group...)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRingFeed(t)
			f.register(0, realRingFd)
			wantRing(t, f.enter(0), 0, realRingFd, realRingFd)
			tc.undo(f)
			wantIndexLabel(t, f.enter(0), 0)
			// Nor did a record that was refused, or a call that was not
			// believed, name the slot it spoke of.
			wantIndexLabel(t, f.enter(1), 1)
		})
	}
}

// What must NOT cost a thread its table: calls that leave the kernel's table
// alone, and the lifetime events of other tasks.
func TestRegisteredRingTableSurvivesUnrelatedEvents(t *testing.T) {
	register := func(opcode uint32, ret int64) func(f *ringFeed) {
		return func(f *ringFeed) {
			f.call(types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER, uint32(realRingFd), opcode, ret, nil)
		}
	}
	tests := []ringLabelCase{
		{"a failed registration", register(ringOpRegister, -22)},
		{"a registration that registered nothing", register(ringOpRegister, 0)},
		{"a failed release", register(ringOpUnregister, -14)},
		{"another opcode returning a count", register(6, 3)},
		{"a release of another index", func(f *ringFeed) { f.unregisterByIndex(7) }},
		{"a registration under another index", func(f *ringFeed) { f.register(1, secondRingFd) }},
		{"another thread exited", func(f *ringFeed) { f.raw(makeThreadExitEvent(f.t, f.time+1, f.pid, f.tid+1)) }},
		{"the group leader exited", func(f *ringFeed) { f.raw(makeThreadExitEvent(f.t, f.time+1, f.pid, f.pid)) }},
		{"another thread exec'd", func(f *ringFeed) {
			f.raw(makeProcessExecEventFrom(f.t, f.time+1, f.pid+50, f.pid+50, f.pid+51, "next"))
		}},
		{"another thread registered", func(f *ringFeed) {
			other := *f
			other.tid += 3
			other.register(0, secondRingFd)
			f.time = other.time
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRingFeed(t)
			f.register(0, realRingFd)
			tc.undo(f)
			wantRing(t, f.enter(0), 0, realRingFd, realRingFd)
		})
	}
}

// A registered ring stays usable after its descriptor is closed, and the
// number may come back for any file. The rows stay the ring's; only the
// descriptor number stops being shown, for good.
func TestRegisteredRingOutlivesItsDescriptor(t *testing.T) {
	const decoy = "/tmp/reused-number"
	tests := map[string]func(f *ringFeed){
		"closed":                    func(f *ringFeed) { f.closeFd(realRingFd) },
		"closed and reused":         func(f *ringFeed) { f.closeFd(realRingFd); reuseFd(f, realRingFd, decoy) },
		"rebound without a close":   func(f *ringFeed) { reuseFd(f, realRingFd, decoy) },
		"reused by another ring":    func(f *ringFeed) { f.closeFd(realRingFd); reuseFd(f, realRingFd, realRingName) },
		"reused, closed, ring back": func(f *ringFeed) { reuseFd(f, realRingFd, decoy); f.closeFd(realRingFd) },
	}
	for name, rebind := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRingFeed(t)
			f.register(0, realRingFd)
			wantRing(t, f.enter(0), 0, realRingFd, realRingFd)
			rebind(f)
			wantRing(t, f.enter(0), 0, realRingFd, -1)
			// Whatever the number is bound to next, it is not this ring's.
			reuseFd(f, realRingFd, realRingName)
			wantRing(t, f.enter(0), 0, realRingFd, -1)
		})
	}
}

// The slot holds a snapshot, not the fd table's live entry: rows share it
// with whoever consumes them, so nothing the descriptor goes through later
// may reach it.
func TestRegisteredRingSnapshotIsNotTheLiveTableEntry(t *testing.T) {
	f := newRingFeed(t)
	f.register(0, realRingFd)
	live, ok := f.el.fdState().get(realRingFd, f.pid)
	if !ok {
		t.Fatal("the ring descriptor left the fd table")
	}
	before := f.enter(0)
	live.(*file.FdFile).SetFlags(0x800 | 2) // O_NONBLOCK|O_RDWR, as a F_SETFL would
	after := f.enter(0)
	if before.File.Flags() != file.Flags(2) || after.File.Flags() != file.Flags(2) {
		t.Fatalf("row flags %v then %v, want the registration's O_RDWR both times", before.File.Flags(), after.File.Flags())
	}
	wantRing(t, after, 0, realRingFd, realRingFd)
}

// reuseFd binds fd of the feed's process to a new file called name.
func reuseFd(f *ringFeed, fd int32, name string) {
	f.el.fdState().set(fd, f.pid, file.NewFd(fd, name, 0))
}

// The release of a slot by a call that addresses the ring through that very
// slot is still that ring's row; every later use of the index is not.
func TestReleasedRingNamesOnlyTheCallThatReleasedIt(t *testing.T) {
	f := newRingFeed(t)
	f.register(0, realRingFd)
	wantRing(t, f.unregisterByIndex(0), 0, realRingFd, realRingFd)
	wantIndexLabel(t, f.enter(0), 0)
	wantIndexLabel(t, f.enter(0), 0)
	// The slot is free for the next ring.
	f.register(0, secondRingFd)
	wantRing(t, f.enter(0), 0, secondRingFd, secondRingFd)
}

// A released slot must not name a later call that merely arrives next, when
// the releasing call's own row never came.
func TestReleasedRingDoesNotNameALaterCall(t *testing.T) {
	f := newRingFeed(t)
	f.register(0, realRingFd)
	f.raw(eventBytes(t, f.record(f.time+1, ringOpUnregister, ringUpdate{0, 0})))
	wantIndexLabel(t, f.enter(0), 0)
}

// Only an io_uring file can be registered, so a descriptor ior knows as
// anything else is not believed, and neither is a number that is none.
func TestRegisteredRingIsNamedOnlyAfterAnIoUringFile(t *testing.T) {
	tests := map[string]uint64{
		"an ordinary file":           uint64(stdinFd),
		"a number past int32":        1 << 31,
		"a number in the upper half": 1<<32 | uint64(realRingFd),
	}
	for name, fd := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRingFeed(t)
			f.register(0, realRingFd)
			f.raw(eventBytes(t, f.record(f.time+1, ringOpRegister, ringUpdate{0, fd})))
			wantIndexLabel(t, f.enter(0), 0)
		})
	}
}

// An index outside the table is never looked up, whatever the table holds.
func TestRegisteredRingIndexOutsideTheTable(t *testing.T) {
	f := newRingFeed(t)
	f.register(15, realRingFd)
	wantRing(t, f.enter(15), 15, realRingFd, realRingFd)
	for _, index := range []uint32{16, 17, 1 << 31, 0xffffffff} {
		ep := f.enter(index)
		if got, want := ep.File.Name(), file.NewRegisteredRing(int32(index)).Name(); got != want {
			t.Errorf("index %d: file = %q, want %q", index, got, want)
		}
	}
}

// The tracker is bounded: a full map is emptied, which costs names, never
// correctness.
func TestRingTrackerIsBounded(t *testing.T) {
	f := newRingFeed(t)
	f.el.ringState().maxTables = 2
	first := f.tid
	for i := range uint32(3) {
		f.tid = first + i
		f.register(0, realRingFd)
	}
	if got := len(f.el.ringState().tables); got != 1 {
		t.Fatalf("tracker holds %d tables after overflowing a cap of 2, want 1", got)
	}
	wantRing(t, f.enter(0), 0, realRingFd, realRingFd)
	f.tid = first
	wantIndexLabel(t, f.enter(0), 0)
}

// A ring named from procfs was not in the fd table when it was registered:
// its number stays the ring's until the table gets an entry for it.
func TestRingSlotFromProcfsLosesItsNumberToATrackedFile(t *testing.T) {
	fds := newFDTracker(nil)
	slot := ringSlot{ring: file.NewFd(7, realRingName, 2)}
	if !slot.stillBound(fds, execCommPid) {
		t.Fatal("an untracked ring descriptor lost its number without any binding")
	}
	fds.set(7, execCommPid+1, file.NewFd(7, "/other/process", 0))
	if !slot.stillBound(fds, execCommPid) {
		t.Fatal("another process's descriptor 7 took the ring's number")
	}
	fds.set(7, execCommPid, file.NewFd(7, "/tmp/newer", 0))
	if slot.stillBound(fds, execCommPid) {
		t.Fatal("the ring kept its number although the fd table bound it to a newer file")
	}
	fds.delete(7, execCommPid)
	if slot.stillBound(fds, execCommPid) {
		t.Fatal("a number given up came back")
	}
}

// The control record belongs between the enter and the exit of its call, so
// a signal handler's io_uring_register must not end an interrupted row's
// wait (eventloop_restart.go).
func TestRingFdsRecordAmendsItsPendingEnter(t *testing.T) {
	if !amendsPendingEnter(&types.RingFdsEvent{}) {
		t.Fatal("a ring-fds record is taken for a record that ends a restart fold")
	}
}

// io_uring_setup names its descriptor without procfs: the process of these
// tests does not exist, so a name can only come from the call itself.
func TestIoUringSetupNamesItsDescriptorWithoutProcfs(t *testing.T) {
	f := newRingFeed(t)
	const ringFd = 11
	ep := f.call(types.SYS_ENTER_IO_URING_SETUP, types.SYS_EXIT_IO_URING_SETUP, 0xffffffff, 0, ringFd, nil)
	if got := ep.File.String(); got != "anon_inode:[io_uring]%(11,O_RDWR|O_CLOEXEC)" {
		t.Fatalf("setup row = %q, want the ring on fd 11, read-write and close-on-exec", got)
	}
	// And a ring registered from it is named.
	f.register(3, ringFd)
	if got := f.enter(3).File.Name(); got != "anon_inode:[io_uring]" {
		t.Fatalf("registered ring = %q, want the name the setup gave its descriptor", got)
	}
}
