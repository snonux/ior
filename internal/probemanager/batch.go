package probemanager

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"ior/internal/tracepoints"
	"ior/internal/types"
)

// SyscallError is one per-syscall failure of a batch attach or detach.
type SyscallError struct {
	Syscall string
	Err     error
}

// BatchResult summarises one batch attach or detach (AttachMatching,
// DetachMatching and the family helpers built on them).
//
// Total is the number of probes the batch had to change: for an attach the
// matching probes that were detached, for a detach the matching probes that
// were attached. Probes already in the requested state are not counted.
// Changed counts the ones that changed without an error; every other one has
// an entry in Errors, in the (sorted) order the batch visited them. For an
// attach those are the probes that stayed detached. For a detach they are
// detached like the rest - a Destroy that reports an error is final too
// (Link) - and only carry the error.
type BatchResult struct {
	Total   int
	Changed int
	Errors  []SyscallError
}

// FamilyState is the attach state of one syscall family: how many of its
// registered probes are active out of how many are registered.
type FamilyState struct {
	Family types.SyscallFamily
	Active int
	Total  int
}

// Err joins the per-syscall errors into one error ("<syscall>: <err>" each),
// or returns nil when every probe of the batch changed state.
func (r BatchResult) Err() error {
	errs := make([]error, 0, len(r.Errors))
	for _, e := range r.Errors {
		errs = append(errs, fmt.Errorf("%s: %w", e.Syscall, e.Err))
	}
	return errors.Join(errs...)
}

// AttachMatching attaches every registered, currently inactive probe whose
// syscall match selects. It is the runtime counterpart of AttachAll's
// shouldAttach: the TUI uses it to attach a whole family after startup.
//
// Unlike AttachAll it never stops at the first failure: attaching dozens of
// tracepoints on a kernel that lacks some of them must still attach the rest,
// so each failure is collected into the result (and, as with every Attach,
// recorded on the probe entry for States). progress, when non-nil, receives
// (0, total) first and then one update after each probe, like
// CloseWithProgress.
//
// ctx cancels the batch between probes: the TUI ties it to the trace session
// whose manager this is, so a restart stops a batch that would otherwise keep
// attaching tracepoints to a module that is about to close (slowing its
// teardown). A cancelled batch returns what it did so far - Changed and
// Errors cover the visited probes only, Total still the whole batch - with
// ctx.Err(). The only other errors returned directly are a nil manager or
// match.
func (m *Manager) AttachMatching(ctx context.Context, match func(syscall string) bool, progress func(completed, total int)) (BatchResult, error) {
	return m.runBatch(ctx, match, false, m.Attach, progress)
}

// DetachMatching detaches every currently active probe whose syscall match
// selects. Cancellation, errors and progress are as for AttachMatching.
func (m *Manager) DetachMatching(ctx context.Context, match func(syscall string) bool, progress func(completed, total int)) (BatchResult, error) {
	return m.runBatch(ctx, match, true, m.Detach, progress)
}

// AttachFamily attaches every inactive probe of family (see AttachMatching).
// Family membership is the attach-time one -trace-families uses
// (tracepoints.SyscallFamily), so the TUI's family toggle and the startup
// flag select exactly the same syscalls.
func (m *Manager) AttachFamily(ctx context.Context, family types.SyscallFamily, progress func(completed, total int)) (BatchResult, error) {
	return m.AttachMatching(ctx, inFamily(family), progress)
}

// DetachFamily detaches every active probe of family (see DetachMatching).
func (m *Manager) DetachFamily(ctx context.Context, family types.SyscallFamily, progress func(completed, total int)) (BatchResult, error) {
	return m.DetachMatching(ctx, inFamily(family), progress)
}

// FamilyStates groups probe states by syscall family and returns one entry
// per family in types.AllSyscallFamilies display order, including families
// with no registered probe (Total 0), so a caller can list all of them.
func FamilyStates(states []ProbeState) []FamilyState {
	families := types.AllSyscallFamilies()
	out := make([]FamilyState, len(families))
	for i, family := range families {
		out[i].Family = family
	}
	for _, state := range states {
		rank := types.SyscallFamilyRank(SyscallFamily(state.Syscall))
		if rank >= len(out) {
			continue // unreachable: SyscallFamily only returns known families
		}
		out[rank].Total++
		if state.Active {
			out[rank].Active++
		}
	}
	return out
}

// SyscallFamily returns the family of a syscall probe key. A syscall the
// generated family table does not know (none today, see the tracepoints
// tests) is reported as Misc, the catch-all family.
func SyscallFamily(syscall string) types.SyscallFamily {
	if family, ok := tracepoints.SyscallFamily(syscall); ok {
		return family
	}
	return types.FamilyMisc
}

// inFamily returns a match predicate selecting the syscalls of family.
func inFamily(family types.SyscallFamily) func(string) bool {
	return func(syscall string) bool { return SyscallFamily(syscall) == family }
}

// runBatch applies change (Attach or Detach) to every probe that match
// selects and whose active state equals wantActive, i.e. every probe the
// batch actually has to change, and collects the per-syscall outcome. It
// checks ctx before each probe and stops at the first check that finds it
// cancelled; a probe already being changed is finished, never interrupted.
func (m *Manager) runBatch(ctx context.Context, match func(string) bool, wantActive bool, change func(string) error, progress func(completed, total int)) (BatchResult, error) {
	if m == nil {
		return BatchResult{}, errors.New("probe manager is nil")
	}
	if match == nil {
		return BatchResult{}, errors.New("batch match predicate is required")
	}
	if progress == nil {
		progress = func(int, int) {}
	}
	syscalls := m.syscallsWhere(match, wantActive)
	result := BatchResult{Total: len(syscalls)}
	progress(0, result.Total)
	for i, syscall := range syscalls {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := change(syscall); err != nil {
			result.Errors = append(result.Errors, SyscallError{Syscall: syscall, Err: err})
		} else {
			result.Changed++
		}
		progress(i+1, result.Total)
	}
	return result, nil
}

// syscallsWhere snapshots, under the manager lock, the sorted syscall keys
// that match selects and whose active state is active. The batch then works
// from the snapshot with the lock released, like Close: Attach and Detach
// take the lock themselves and re-validate each entry.
func (m *Manager) syscallsWhere(match func(string) bool, active bool) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for syscall, entry := range m.probes {
		if entry.active == active && match(syscall) {
			out = append(out, syscall)
		}
	}
	slices.Sort(out)
	return out
}
