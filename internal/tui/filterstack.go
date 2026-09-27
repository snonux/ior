package tui

import (
	"strings"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
)

// maxFilterHistory is the maximum number of undo levels retained by filterStack.
// Once this cap is reached, the oldest entry is evicted so the slices never
// grow without bound across long-running sessions or automated filter changes.
const maxFilterHistory = 50

// filterStack manages the trace filter chain: the active filter, the undo
// history, and the human-readable label stack displayed in the status bar.
// It owns all filter mutation and label-generation logic so the top-level
// Model only coordinates between filterStack, TraceLifecycle, and the dashboard.
type filterStack struct {
	global  globalfilter.Filter
	history []globalfilter.Filter
	stack   []string
}

// newFilterStack constructs a filterStack seeded with the given initial filter.
func newFilterStack(initial globalfilter.Filter) filterStack {
	return filterStack{global: initial.Clone()}
}

// current returns the currently active filter (read-only copy).
func (f *filterStack) current() globalfilter.Filter {
	return f.global
}

// push records oldFilter in the history stack, sets global to newFilter, and
// appends an action label. Returns true when the filter actually changed.
// When the history depth would exceed maxFilterHistory the oldest entry is
// evicted from both slices to keep memory usage bounded.
func (f *filterStack) push(newFilter globalfilter.Filter, action string) bool {
	next := newFilter.Clone()
	if f.global.Equal(next) {
		return false
	}
	f.history = append(f.history, f.global.Clone())
	f.stack = append(f.stack, globalFilterActionLabel(f.global, next, action))
	// Evict the oldest undo level once the cap is exceeded so the slices
	// never grow without bound across long-running sessions.
	if len(f.history) > maxFilterHistory {
		f.history = f.history[1:]
		f.stack = f.stack[1:]
	}
	f.global = next
	return true
}

// pop reverts to the previous filter. Returns (previousFilter, true) when
// history is available, or (zero, false) when already at the oldest entry.
func (f *filterStack) pop() (globalfilter.Filter, bool) {
	if len(f.history) == 0 {
		return globalfilter.Filter{}, false
	}
	prev := f.history[len(f.history)-1]
	f.history = f.history[:len(f.history)-1]
	if len(f.stack) > 0 {
		f.stack = f.stack[:len(f.stack)-1]
	}
	f.global = prev.Clone()
	return prev, true
}

// setGlobal directly replaces the active filter without recording history.
// Use this when restoring a known filter (e.g. from pop).
func (f *filterStack) setGlobal(filter globalfilter.Filter) {
	f.global = filter.Clone()
}

// rebindProcessFilters replaces the PID and TID equality constraints on every
// entry in both the active filter and the full history. Call this whenever the
// traced process changes so earlier undo states cannot restore a stale PID.
func (f *filterStack) rebindProcessFilters(pid, tid int) {
	f.global = applyProcessFilters(f.global, pid, tid)
	for i := range f.history {
		f.history[i] = applyProcessFilters(f.history[i], pid, tid)
	}
}

// pidFromFilter extracts the PID equality value from the active filter.
// Returns -1 (meaning "no filter") when no equality constraint is set.
func (f *filterStack) pidFromFilter() int {
	// EqValue returns int64; PID values are always within int range (Linux PID_MAX ≤ 4194304).
	pid, _ := f.global.PID.EqValue()
	return selectedPIDFilter(int(pid))
}

// tidFromFilter extracts the TID equality value from the active filter.
// Returns -1 (meaning "no filter") when no equality constraint is set.
func (f *filterStack) tidFromFilter() int {
	// EqValue returns int64; TID values are always within int range (Linux PID_MAX ≤ 4194304).
	tid, _ := f.global.TID.EqValue()
	return selectedPIDFilter(int(tid))
}

// labelStack returns the current human-readable filter label stack (read-only).
func (f *filterStack) labelStack() []string {
	return f.stack
}

// applyProcessFilters clones the filter and replaces its PID/TID equality
// constraints with the supplied values. Called by rebindProcessFilters and
// during the PID/TID reselect flow.
func applyProcessFilters(filter globalfilter.Filter, pid, tid int) globalfilter.Filter {
	out := filter.Clone()
	out.PID = globalfilter.NewEqFilter(int64(pid))
	out.TID = globalfilter.NewEqFilter(int64(tid))
	return out
}

// globalFilterActionLabel builds a short human-readable summary of what
// changed between prev and next. If action is non-empty it is returned as-is.
// Every per-dimension token comes from presenter.DimensionSummary, so a
// derived label uses exactly the wording the filter's own summary uses: a
// dimension changed when its canonical token changed, and a dimension whose
// token vanished is reported as "clear <name>".
func globalFilterActionLabel(prev, next globalfilter.Filter, action string) string {
	if strings.TrimSpace(action) != "" {
		return action
	}
	parts := make([]string, 0, 12)
	if prev.ErrorsOnly != next.ErrorsOnly {
		if next.ErrorsOnly {
			parts = append(parts, "errors")
		} else {
			parts = append(parts, "clear errors")
		}
	}
	for _, d := range presenter.Dimensions() {
		before := presenter.DimensionSummary(prev, d)
		after := presenter.DimensionSummary(next, d)
		switch {
		case before == after:
			// Unchanged dimension: nothing to report.
		case after == "":
			parts = append(parts, "clear "+d.Name())
		default:
			parts = append(parts, after)
		}
	}
	if len(parts) == 0 {
		return presenter.FilterSummary(next)
	}
	return strings.Join(parts, " ")
}
