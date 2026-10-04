package internal

import (
	"math"
	"os"

	"ior/internal/event"
	"ior/internal/types"
)

// Address-space accounting (Pair.AddressSpaceBytes, parquet address_space_bytes,
// Snapshot.TotalAddressSpaceBytes).
//
// The metric answers "how much virtual address space did this call add to,
// remove from or move within the process", kept apart from the I/O byte
// counters. Which syscalls belong to it is a deliberate decision:
//
//   - mmap: the size of the new mapping.
//   - munmap: the size of the range released.
//   - mremap: the larger of the old and new size (the extent the call touched).
//   - brk: how far the program break moved (see brkTracker).
//
// Calls that only operate on an existing range - msync (flush), mprotect and
// pkey_mprotect (permissions), madvise (hints), mlock/mlock2 (pinning) - leave
// the address space exactly as large as before, so they report 0. msync used
// to be counted while its siblings were not, which made the total depend on
// whether a program flushed its mappings rather than on how much it mapped.
//
// Every length is rounded up to the host page size: the kernel maps and
// unmaps whole pages (mmap(len=1) maps 4096 bytes, munmap(len=1) releases
// 4096), so the requested length under-reports what actually changed. ior
// traces the host it runs on, so the host page size is the traced one. Huge
// page mappings (MAP_HUGETLB) round to the huge page size instead; the capture
// carries no such distinction, so those stay at base-page granularity.

// hostPageSize is the base page size of the traced host.
var hostPageSize = uint64(os.Getpagesize())

// roundUpToPage rounds n up to a multiple of page (a power of two). A value
// within one page of overflowing is returned unchanged rather than wrapping
// to zero; the kernel rejects such lengths, and only successful calls are
// accounted, so that case does not arise from a real trace.
func roundUpToPage(n, page uint64) uint64 {
	if page == 0 || n > math.MaxUint64-(page-1) {
		return n
	}
	return (n + page - 1) &^ (page - 1)
}

// applyAddressSpaceBytes sets the address-space extent of a successful
// mmap/munmap/mremap pair. Failed calls (errno return) changed nothing and stay
// at 0. brk is stateful and handled by eventLoop.applyBrkGrowth instead.
func applyAddressSpaceBytes(ep *event.Pair) {
	if ep == nil {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || event.IsErrnoRet(retEv.Ret) {
		return
	}
	switch enterEv := ep.EnterEv.(type) {
	case *types.MemEvent:
		ep.AddressSpaceBytes = addressSpaceBytesFromMem(enterEv.TraceId, enterEv.Length, enterEv.Length2)
	case *types.MmapEvent:
		ep.AddressSpaceBytes = addressSpaceBytesFromMem(enterEv.TraceId, enterEv.Length, 0)
	}
}

// addressSpaceBytesFromMem maps a memory syscall's captured lengths to the
// page-rounded extent it changed; see the package comment above for which
// syscalls count.
func addressSpaceBytesFromMem(traceID types.TraceId, length, length2 uint64) uint64 {
	switch traceID {
	case types.SYS_ENTER_MMAP, types.SYS_ENTER_MUNMAP:
		return roundUpToPage(length, hostPageSize)
	case types.SYS_ENTER_MREMAP:
		return roundUpToPage(max(length, length2), hostPageSize)
	default:
		return 0
	}
}

// applyBrkGrowth sets the address-space extent of a brk pair from the movement
// of the process's program break.
//
// brk carries no length: its argument is the requested new break and its
// return value is the break in effect afterwards (the unchanged old break when
// the request failed, not an errno). The extent is therefore the difference to
// the previous break of the same process, which the loop remembers. Growth and
// shrinkage both count, mirroring mmap and munmap.
func (e *eventLoop) applyBrkGrowth(ep *event.Pair) {
	if ep == nil {
		return
	}
	enterEv, ok := ep.EnterEv.(*types.MemEvent)
	if !ok || enterEv.TraceId != types.SYS_ENTER_BRK {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || event.IsErrnoRet(retEv.Ret) {
		return
	}
	ep.AddressSpaceBytes = e.brkState.observe(enterEv.Pid, enterEv.Addr, uint64(retEv.Ret))
}

// maxTrackedBreaks bounds brkTracker. Entries are dropped when a process
// exits or execs, so the map normally holds only the live traced processes;
// the cap covers records lost to ring-buffer backpressure. Clearing it costs
// each live process one uncounted brk (its next call just re-baselines).
const maxTrackedBreaks = 1 << 16

// brkTracker remembers the last observed program break per process (tgid: the
// break belongs to the address space, which threads share). The zero value is
// ready to use. Only the event-loop goroutine touches it.
//
// Accepted approximation: the key is the tgid, not the mm. A CLONE_VM child
// that is its own thread group (vfork, posix_spawn, clone(CLONE_VM) without
// CLONE_THREAD) has a tgid of its own but shares the parent's address space
// and therefore its break. The child's first brk thus only baselines to 0 (it
// reports nothing for heap movement it caused), and the parent's baseline goes
// stale while the child moves the shared break, so the parent's next brk
// attributes that movement to itself. Exec clears the child's baseline, which
// is the common vfork case (the child execs at once and gets a fresh mm).
// Tracking the mm would need an identity the capture does not carry.
type brkTracker struct {
	breaks map[uint32]uint64
}

// observe records newBreak as pid's break and returns by how many bytes it
// moved, in whole pages (the kernel grows and shrinks the heap VMA in pages,
// so two sub-page adjustments inside one page move nothing).
//
// It returns 0, only baselining, when there is nothing trustworthy to
// subtract from: the first brk seen for the process (ior may have attached
// mid-run, or the process was forked and inherited its parent's break), and
// any brk(0) query, which merely reports the current break - after an exec
// that is the fresh break of the new address space, so a stale baseline can
// never turn into a bogus delta. A lost or filtered brk in between needs no
// special care: the next observed call measures against the last one seen and
// so reports the accumulated movement.
func (t *brkTracker) observe(pid uint32, requested, newBreak uint64) uint64 {
	prev, known := t.breaks[pid]
	if t.breaks == nil || (!known && len(t.breaks) >= maxTrackedBreaks) {
		t.breaks = make(map[uint32]uint64)
	}
	t.breaks[pid] = newBreak
	if !known || requested == 0 {
		return 0
	}
	oldPages, newPages := roundUpToPage(prev, hostPageSize), roundUpToPage(newBreak, hostPageSize)
	if newPages >= oldPages {
		return newPages - oldPages
	}
	return oldPages - newPages
}

// forget drops pid's baseline: the process exited or exec'd, so the next brk
// starts a new address space.
func (t *brkTracker) forget(pid uint32) {
	delete(t.breaks, pid)
}
