//go:build !race

package internal

import (
	"syscall"
	"testing"

	"ior/internal/file"
)

// TestFdIndexChurnDoesNotAllocate pins the steady state the idle-entry list
// exists for: once warmed up, a process repeatedly opening and closing its
// only tracked descriptor, and a stream of short-lived processes each
// registering and exiting, cost no heap allocation in the index. Excluded
// under -race, whose instrumentation can allocate on its own.
func TestFdIndexChurnDoesNotAllocate(t *testing.T) {
	fdt := newFDTracker(nil)
	f := file.NewFd(3, "/churn", syscall.O_RDONLY)
	churn := func() {
		fdt.set(3, crossPidA, f)
		fdt.delete(3, crossPidA)
	}
	churn()
	if allocs := testing.AllocsPerRun(1000, churn); allocs != 0 {
		t.Fatalf("set/delete churn of one pid allocates %.1f times per op, want 0", allocs)
	}

	pid := uint32(crossPidB)
	lifecycle := func() {
		pid++
		fdt.set(3, pid, f)
		fdt.setProcFdCache(4, pid, f)
		fdt.deletePid(pid)
	}
	lifecycle()
	if allocs := testing.AllocsPerRun(1000, lifecycle); allocs != 0 {
		t.Fatalf("new-pid register/exit allocates %.1f times per op, want 0", allocs)
	}
}
