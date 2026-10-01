package sampling

import "sync"

// Tally counts the exact population of the sampled syscalls over one window
// whose start and end the caller chooses, by syscall name. A TUI Parquet
// recording (the R key) owns one per recording: its rows are counted as
// traced where the recorder writes them, the kernel aggregate counts drained
// while it runs are added as counted-only, and Summary renders the result at
// stop. Each recording gets a fresh Tally, so its totals are that recording's
// deltas, never counts since the trace started.
//
// The raw output modes keep their own trace-ID keyed tally in package internal
// (samplingTally), because their traced count sits on the per-event hot path;
// both render through the same Summary, so the footer format is shared.
//
// All methods are safe for concurrent use and a nil *Tally ignores every call
// (and summarises as "nothing sampled"), so callers need no nil checks.
type Tally struct {
	mu sync.Mutex
	// plan holds every sampled syscall the tally counts, by name, with its
	// Rate and Family; Traced and Counted stay zero (the counts live below).
	plan map[string]Entry
	// attached marks the syscalls whose probe was attached when the tally
	// started. Only they make up Plan's rates (see NewTally).
	attached map[string]bool
	traced   map[string]uint64
	counted  map[string]uint64
	// lowerBound and unavailable become Summary's LowerBound and Unavailable;
	// unavailable keeps the first reason given.
	lowerBound  bool
	unavailable string
}

// NewTally starts a tally of entries (one per sampled syscall; only Syscall,
// Rate and Family are used). attached reports whether a syscall's probe is
// attached right now; nil means all of them are. It decides only which rates
// Plan reports - the rates are written when a recording starts, and a syscall
// that is not traced then has no rate worth announcing. Every entry is still
// counted, so a sampled syscall whose probe is attached later during the
// window shows up in Summary once it was invoked. NewTally returns nil, the
// "nothing sampled" tally, when entries is empty.
func NewTally(entries []Entry, attached func(syscall string) bool) *Tally {
	if len(entries) == 0 {
		return nil
	}
	t := &Tally{
		plan:     make(map[string]Entry, len(entries)),
		attached: make(map[string]bool, len(entries)),
		traced:   make(map[string]uint64, len(entries)),
		counted:  make(map[string]uint64, len(entries)),
	}
	for _, e := range entries {
		t.plan[e.Syscall] = Entry{Syscall: e.Syscall, Rate: e.Rate, Family: e.Family}
		t.attached[e.Syscall] = attached == nil || attached(e.Syscall)
	}
	return t
}

// CountTraced records one invocation of syscall that became an output row.
// Syscalls the tally does not sample are ignored.
func (t *Tally) CountTraced(syscall string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.plan[syscall]; ok {
		t.traced[syscall]++
	}
}

// CountUntraced adds n invocations of syscall that only the kernel's aggregate
// counter saw (no row exists for them). Syscalls the tally does not sample are
// ignored.
func (t *Tally) CountUntraced(syscall string, n uint64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.plan[syscall]; ok {
		t.counted[syscall] += n
	}
}

// MarkLowerBound records that events were lost during the window (ring-buffer
// drops, rows shed by a full recorder queue, ...): the counts are then a lower
// bound (Summary.LowerBound).
func (t *Tally) MarkLowerBound() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lowerBound = true
}

// MarkUnavailable records that the counts of the window cannot be trusted at
// all, and why (Summary.Unavailable). The first reason is kept.
func (t *Tally) MarkUnavailable(reason string) {
	if t == nil || reason == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.unavailable == "" {
		t.unavailable = reason
	}
}

// Plan is the summary as known when the window starts: the rates of the
// sampled syscalls that were attached then, no counts. Only its Rates() are
// meaningful (it is what goes into the Parquet ior.sampling key).
func (t *Tally) Plan() Summary {
	if t == nil {
		return Summary{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := make([]Entry, 0, len(t.plan))
	for name, e := range t.plan {
		if t.attached[name] {
			entries = append(entries, e)
		}
	}
	return New(entries, "the recording has not finished")
}

// Summary renders the counts so far: every syscall attached at the start
// (New keeps the own-rate ones even when nothing was counted) plus every other
// sampled syscall that was invoked during the window. Call it once the window
// has ended and its last counts were added.
func (t *Tally) Summary() Summary {
	if t == nil {
		return Summary{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := make([]Entry, 0, len(t.plan))
	for name, e := range t.plan {
		e.Traced, e.Counted = t.traced[name], t.counted[name]
		if t.attached[name] || e.Total() > 0 {
			entries = append(entries, e)
		}
	}
	summary := New(entries, t.unavailable)
	if t.lowerBound {
		return summary.AtLeast()
	}
	return summary
}
