package tui

import (
	"ior/internal/globalfilter"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// familyCycleAll is the sentinel rank for the "all families / unscoped" state
// that sits between the last family (Misc) and the first (Network) in the
// [/] cycle. The cycle space is therefore the families in
// types.AllSyscallFamilies() (ranks 0..N-1) plus this -1 slot.
const familyCycleAll = -1

// currentFamilyRank derives the active position in the family cycle purely from
// the supplied filter: an unset Family means the "all" state (-1), otherwise the
// stable display rank of the scoped family.
func currentFamilyRank(filter globalfilter.Filter) int {
	if filter.Family == nil {
		return familyCycleAll
	}
	return types.SyscallFamilyRank(types.SyscallFamily(filter.Family.Pattern))
}

// stepFamilyRank advances (delta +1) or reverses (delta -1) through the family
// cycle, wrapping across the "all" sentinel: ... Misc -> all -> Network ... The
// returned rank is familyCycleAll or a valid index into AllSyscallFamilies().
func stepFamilyRank(current, delta int) int {
	size := len(types.AllSyscallFamilies()) + 1 // +1 for the "all" state
	// Shift into a contiguous 0..size-1 space (all=0, families=1..N), step
	// with wrap, then shift back so "all" maps to familyCycleAll.
	next := (current + 1 + delta + size) % size
	return next - 1
}

// familyForRank returns the family string for a cycle rank, or "" for the
// "all" state (rank familyCycleAll / any out-of-range rank).
func familyForRank(rank int) string {
	families := types.AllSyscallFamilies()
	if rank < 0 || rank >= len(families) {
		return ""
	}
	return string(families[rank])
}

// cycleFamilyScope re-scopes the whole dashboard to the next/prev syscall
// family. It derives the current position statelessly from the active filter,
// clones it so every other filter component is preserved, sets or clears the
// Family component, and applies the result as a REPLACEMENT (no undo-stack
// push) so the stack label does not grow as the user cycles.
func (m Model) cycleFamilyScope(delta int) (tea.Model, tea.Cmd) {
	scoped := m.filters.current().Clone()
	nextRank := stepFamilyRank(currentFamilyRank(scoped), delta)
	if family := familyForRank(nextRank); family != "" {
		scoped.Family = &globalfilter.StringFilter{Pattern: family}
	} else {
		scoped.Family = nil
	}
	return m.replaceGlobalFilter(scoped)
}
