package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"ior/internal/globalfilter"
)

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
func (f *filterStack) push(newFilter globalfilter.Filter, action string) bool {
	next := newFilter.Clone()
	if f.global.Equal(next) {
		return false
	}
	f.history = append(f.history, f.global.Clone())
	f.stack = append(f.stack, globalFilterActionLabel(f.global, next, action))
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
	pid, _ := f.global.PID.EqValue()
	return selectedPIDFilter(pid)
}

// tidFromFilter extracts the TID equality value from the active filter.
// Returns -1 (meaning "no filter") when no equality constraint is set.
func (f *filterStack) tidFromFilter() int {
	tid, _ := f.global.TID.EqValue()
	return selectedPIDFilter(tid)
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
func globalFilterActionLabel(prev, next globalfilter.Filter, action string) string {
	if strings.TrimSpace(action) != "" {
		return action
	}
	parts := make([]string, 0, 10)
	if prev.ErrorsOnly != next.ErrorsOnly {
		if next.ErrorsOnly {
			parts = append(parts, "errors")
		} else {
			parts = append(parts, "clear errors")
		}
	}
	parts = appendStringFilterChange(parts, "syscall", prev.Syscall, next.Syscall)
	parts = appendStringFilterChange(parts, "comm", prev.Comm, next.Comm)
	parts = appendStringFilterChange(parts, "file", prev.File, next.File)
	parts = appendNumericFilterChange(parts, "pid", prev.PID, next.PID, false)
	parts = appendNumericFilterChange(parts, "tid", prev.TID, next.TID, false)
	parts = appendNumericFilterChange(parts, "fd", prev.FD, next.FD, false)
	parts = appendNumericFilterChange(parts, "latency", prev.LatencyNs, next.LatencyNs, true)
	parts = appendNumericFilterChange(parts, "gap", prev.GapNs, next.GapNs, true)
	parts = appendNumericFilterChange(parts, "bytes", prev.Bytes, next.Bytes, false)
	parts = appendNumericFilterChange(parts, "ret", prev.RetVal, next.RetVal, false)
	if len(parts) == 0 {
		return next.Summary()
	}
	return strings.Join(parts, " ")
}

func appendStringFilterChange(parts []string, name string, prev, next *globalfilter.StringFilter) []string {
	if sameStringFilter(prev, next) {
		return parts
	}
	if next == nil || strings.TrimSpace(next.Pattern) == "" {
		return append(parts, "clear "+name)
	}
	return append(parts, fmt.Sprintf("%s~%s", name, strings.TrimSpace(next.Pattern)))
}

func appendNumericFilterChange(parts []string, name string, prev, next *globalfilter.NumericFilter, duration bool) []string {
	if sameNumericFilter(prev, next) {
		return parts
	}
	if next == nil {
		return append(parts, "clear "+name)
	}
	value := strconv.FormatInt(next.Value, 10)
	if duration {
		value = time.Duration(next.Value).String()
	}
	return append(parts, fmt.Sprintf("%s%s%s", name, globalfilter.CompareOpSymbol(next.Op), value))
}

func sameStringFilter(a, b *globalfilter.StringFilter) bool {
	if a == nil || strings.TrimSpace(a.Pattern) == "" {
		return b == nil || strings.TrimSpace(b.Pattern) == ""
	}
	if b == nil {
		return false
	}
	return strings.TrimSpace(a.Pattern) == strings.TrimSpace(b.Pattern)
}

func sameNumericFilter(a, b *globalfilter.NumericFilter) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Op == b.Op && a.Value == b.Value
}
