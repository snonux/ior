package internal

import (
	"math"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// pg is the host page size the production code rounds to; tests express every
// expectation in multiples of it so they hold on 4K, 16K and 64K page hosts.
var pg = hostPageSize

func TestRoundUpToPage(t *testing.T) {
	tests := []struct {
		name    string
		n, page uint64
		want    uint64
	}{
		{"zero stays zero", 0, 4096, 0},
		{"one byte is one page", 1, 4096, 4096},
		{"exact page is unchanged", 4096, 4096, 4096},
		{"one over a page", 4097, 4096, 8192},
		{"64K pages", 1, 65536, 65536},
		{"near overflow is returned as is, not wrapped to 0", math.MaxUint64 - 1, 4096, math.MaxUint64 - 1},
		{"zero page size is a no-op", 123, 0, 123},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roundUpToPage(tt.n, tt.page); got != tt.want {
				t.Fatalf("roundUpToPage(%d, %d) = %d, want %d", tt.n, tt.page, got, tt.want)
			}
		})
	}
}

// TestAddressSpaceBytesRoundsToPages pins the fix for the requested-length
// under-count: mmap(len=1) maps a whole page and munmap(len=1) releases one.
func TestAddressSpaceBytesRoundsToPages(t *testing.T) {
	tests := []struct {
		name            string
		traceID         types.TraceId
		length, length2 uint64
		want            uint64
	}{
		{"mmap of one byte maps a page", types.SYS_ENTER_MMAP, 1, 0, pg},
		{"munmap of one byte releases a page", types.SYS_ENTER_MUNMAP, 1, 0, pg},
		{"mmap just over a page", types.SYS_ENTER_MMAP, pg + 1, 0, 2 * pg},
		{"mremap grows: rounded new size", types.SYS_ENTER_MREMAP, 1, pg + 1, 2 * pg},
		{"mremap shrinks: rounded old size", types.SYS_ENTER_MREMAP, pg + 1, 1, 2 * pg},
		{"msync leaves the extent alone", types.SYS_ENTER_MSYNC, 3 * pg, 0, 0},
		{"mprotect leaves the extent alone", types.SYS_ENTER_MPROTECT, 3 * pg, 0, 0},
		{"madvise leaves the extent alone", types.SYS_ENTER_MADVISE, 3 * pg, 0, 0},
		{"mlock leaves the extent alone", types.SYS_ENTER_MLOCK, 3 * pg, 0, 0},
		{"brk is stateful, not a length", types.SYS_ENTER_BRK, 3 * pg, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addressSpaceBytesFromMem(tt.traceID, tt.length, tt.length2); got != tt.want {
				t.Fatalf("addressSpaceBytesFromMem() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBrkTrackerObserve(t *testing.T) {
	const pidA, pidB = uint32(100), uint32(200)
	base := 100 * pg
	var tr brkTracker

	// The first sighting only baselines: ior cannot know the previous break.
	if got := tr.observe(pidA, base, base); got != 0 {
		t.Fatalf("first brk = %d, want 0", got)
	}
	// Growth by three pages.
	if got := tr.observe(pidA, base+3*pg, base+3*pg); got != 3*pg {
		t.Fatalf("grow = %d, want %d", got, 3*pg)
	}
	// Sub-page adjustments inside the already mapped last page move nothing.
	if got := tr.observe(pidA, base+3*pg-100, base+3*pg-100); got != 0 {
		t.Fatalf("sub-page shrink = %d, want 0", got)
	}
	// A whole-page shrink counts like a munmap would.
	if got := tr.observe(pidA, base+pg, base+pg); got != 2*pg {
		t.Fatalf("shrink = %d, want %d", got, 2*pg)
	}
	// A refused request returns the unchanged break: no movement.
	if got := tr.observe(pidA, base+50*pg, base+pg); got != 0 {
		t.Fatalf("failed grow = %d, want 0", got)
	}
	// A brk(0) query only re-baselines, even when the break differs (an
	// exec whose record was lost), so no bogus delta appears.
	if got := tr.observe(pidA, 0, base+90*pg); got != 0 {
		t.Fatalf("brk(0) query = %d, want 0", got)
	}
	if got := tr.observe(pidA, base+91*pg, base+91*pg); got != pg {
		t.Fatalf("grow after query = %d, want %d", got, pg)
	}
	// Processes are independent.
	if got := tr.observe(pidB, base, base+7*pg); got != 0 {
		t.Fatalf("other pid first brk = %d, want 0", got)
	}

	tr.forget(pidA)
	if got := tr.observe(pidA, base+200*pg, base+200*pg); got != 0 {
		t.Fatalf("brk after forget = %d, want 0 (re-baselined)", got)
	}
}

func TestBrkTrackerIsBounded(t *testing.T) {
	var tr brkTracker
	for pid := uint32(1); pid <= maxTrackedBreaks+10; pid++ {
		tr.observe(pid, pg, pg)
	}
	if len(tr.breaks) > maxTrackedBreaks {
		t.Fatalf("tracker holds %d entries, cap is %d", len(tr.breaks), maxTrackedBreaks)
	}
}

func brkPair(pid uint32, requested uint64, ret int64) *event.Pair {
	return &event.Pair{
		EnterEv: &types.MemEvent{TraceId: types.SYS_ENTER_BRK, Pid: pid, Addr: requested},
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_BRK, Pid: pid, Ret: ret},
	}
}

func TestApplyBrkGrowth(t *testing.T) {
	el := &eventLoop{}
	base := 1000 * pg
	steps := []struct {
		name      string
		requested uint64
		ret       int64
		want      uint64
	}{
		{"brk(0) baselines", 0, int64(base), 0},
		{"heap grows two pages", base + 2*pg, int64(base + 2*pg), 2 * pg},
		{"heap shrinks one page", base + pg, int64(base + pg), pg},
		{"errno return changes nothing", base + 9*pg, -12, 0},
	}
	for _, s := range steps {
		ep := brkPair(42, s.requested, s.ret)
		el.applyBrkGrowth(ep)
		if ep.AddressSpaceBytes != s.want {
			t.Fatalf("%s: AddressSpaceBytes = %d, want %d", s.name, ep.AddressSpaceBytes, s.want)
		}
	}

	// A non-brk pair and nil are ignored.
	el.applyBrkGrowth(nil)
	mm := &event.Pair{
		EnterEv: &types.MemEvent{TraceId: types.SYS_ENTER_MPROTECT, Pid: 42, Length: 5 * pg},
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_MPROTECT, Pid: 42},
	}
	el.applyBrkGrowth(mm)
	if mm.AddressSpaceBytes != 0 {
		t.Fatalf("mprotect AddressSpaceBytes = %d, want 0", mm.AddressSpaceBytes)
	}
}

// TestBrkBaselineIsEvictedOnExecAndProcessDeath drives the real control-record
// handlers: a stale baseline surviving an exec or a pid reuse would turn the
// new address space's first brk into a bogus, huge delta. The exit cases cover
// the three group_dead states: known and set (whole process gone), unknown (a
// legacy 24-byte record from a BPF object older than the flag, which evicts
// the tgid's state on every exit as that userspace did) and known but clear
// (a thread exits while its siblings live, so the shared break must survive).
func TestBrkBaselineIsEvictedOnExecAndProcessDeath(t *testing.T) {
	const pid, tid = uint32(4242), uint32(4242)
	tests := []struct {
		name     string
		rec      func(t *testing.T) []byte
		wantKept bool
	}{
		{"exec", func(t *testing.T) []byte { return makeProcessExecEvent(t, defaulTime, pid, tid, "prog") }, false},
		{"group-dead exit", func(t *testing.T) []byte { return makeProcessExitEvent(t, defaulTime, pid, tid) }, false},
		{"legacy exit with unknown group_dead", func(t *testing.T) []byte {
			// The legacy layout is the current one minus group_dead and
			// reserved, so a record cut to 24 bytes is byte-identical to it.
			return makeThreadExitEvent(t, defaulTime, pid, tid+1)[:24]
		}, false},
		{"thread exit keeps the baseline", func(t *testing.T) []byte { return makeThreadExitEvent(t, defaulTime, pid, tid+1) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.brkState.observe(pid, 0, 10*pg)
			out := make(chan *event.Pair, 1)
			el.processRawEvent(tt.rec(t), out)

			if _, kept := el.brkState.breaks[pid]; kept != tt.wantKept {
				t.Fatalf("baseline kept = %v, want %v", kept, tt.wantKept)
			}
		})
	}
}

// brkCaller feeds brk enter/exit record pairs through the real event loop, one
// call per (pid, tid) thread, and returns the resulting Pair.AddressSpaceBytes.
type brkCaller struct {
	t   *testing.T
	el  *eventLoop
	out chan *event.Pair
	now uint64
}

func newBrkCaller(t *testing.T) *brkCaller {
	return &brkCaller{
		t: t, el: newFilteredEventLoop(t, globalfilter.Filter{}),
		out: make(chan *event.Pair, 4), now: uint64(defaulTime),
	}
}

func (c *brkCaller) call(pid, tid uint32, requested uint64, ret int64) uint64 {
	c.t.Helper()
	enter := types.MemEvent{
		EventType: types.ENTER_MEM_EVENT, TraceId: types.SYS_ENTER_BRK,
		Time: c.now, Pid: pid, Tid: tid, Addr: requested,
	}
	enterRaw, err := enter.Bytes()
	if err != nil {
		c.t.Fatal(err)
	}
	_, exitRaw := makeExitRetEvent(c.t, c.now+50, pid, tid, types.SYS_EXIT_BRK, ret)
	c.now += 100
	c.el.processRawEvent(enterRaw, c.out)
	c.el.processRawEvent(exitRaw, c.out)
	ep := <-c.out
	defer ep.Recycle()
	return ep.AddressSpaceBytes
}

// TestBrkPairFlowsThroughTheEventLoop checks the whole path from raw enter and
// exit records to Pair.AddressSpaceBytes, including that the derived value is
// computed for every brk pair (the tracker sits in applyDerivedPairValues).
func TestBrkPairFlowsThroughTheEventLoop(t *testing.T) {
	c := newBrkCaller(t)
	base := 500 * pg

	if got := c.call(defaultPid, defaultTid, 0, int64(base)); got != 0 {
		t.Fatalf("brk(0) = %d, want 0", got)
	}
	if got := c.call(defaultPid, defaultTid, base+4*pg, int64(base+4*pg)); got != 4*pg {
		t.Fatalf("grow = %d, want %d", got, 4*pg)
	}
}

// TestBrkBaselineIsKeyedByProcessNotThread pins the tgid keying: the program
// break belongs to the address space, which all threads of a process share, so
// a brk on a second thread must measure against the break the first thread
// left, while another process has a baseline of its own. Keying by tid instead
// would re-baseline every thread and report 0 for the second thread's growth.
func TestBrkBaselineIsKeyedByProcessNotThread(t *testing.T) {
	const pidA, tidA1, tidA2, pidB, tidB = uint32(7000), uint32(7000), uint32(7001), uint32(8000), uint32(8000)
	c := newBrkCaller(t)
	base := 500 * pg

	if got := c.call(pidA, tidA1, 0, int64(base)); got != 0 {
		t.Fatalf("thread 1 brk(0) = %d, want 0", got)
	}
	if got := c.call(pidA, tidA2, base+3*pg, int64(base+3*pg)); got != 3*pg {
		t.Fatalf("thread 2 growth = %d, want %d (against thread 1's baseline)", got, 3*pg)
	}
	// A first brk of a different process only baselines, however far its
	// break is from the other process's.
	if got := c.call(pidB, tidB, 900*pg, int64(900*pg)); got != 0 {
		t.Fatalf("other process first brk = %d, want 0", got)
	}
	if got := c.call(pidA, tidA1, base+5*pg, int64(base+5*pg)); got != 2*pg {
		t.Fatalf("thread 1 growth after thread 2 = %d, want %d", got, 2*pg)
	}
	if got := c.call(pidB, tidB, 903*pg, int64(903*pg)); got != 3*pg {
		t.Fatalf("other process growth = %d, want %d", got, 3*pg)
	}
}
