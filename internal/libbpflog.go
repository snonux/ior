package internal

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	bpf "github.com/aquasecurity/libbpfgo"

	"ior/internal/flags"
)

// libbpfDebugEnv re-enables the libbpf INFO and DEBUG output that ior drops by
// default (any value except empty, 0, false, no or off, see
// libbpfDebugRequested). It is read for the headless modes only: in TUI mode
// stderr is the Bubble Tea screen, so unfiltered libbpf lines would corrupt
// it. The name lives in the flags package so the -h epilogue and this reader
// cannot drift apart.
const libbpfDebugEnv = flags.LibbpfDebugEnv

const (
	// maxRoutedWarnings caps how many libbpf WARN lines one TUI setup turns
	// into warning rows; the rest are counted and summarised in one row.
	maxRoutedWarnings = 16
	// maxRoutedWarningBytes truncates each routed row. A failed program load
	// is reported as ONE WARN holding the whole verifier log (multi-line, up
	// to megabytes), which would otherwise become a single dashboard row of
	// that size. Headless stderr and the returned load error keep the full
	// text; only the TUI's setup-warning row is shortened.
	maxRoutedWarningBytes = 512
)

// libbpfLogger is the one destination for everything libbpf prints, in every
// mode.
//
// libbpfgo's default logger writes every libbpf level to stderr. Loading the
// embedded object makes libbpf emit ~23.5k DEBUG lines (2.6 MB: the ELF
// section walk, CO-RE relocation trace, one line per map/program), which
// buried ior's own warnings and statistics on every -plain, -flamegraph and
// -parquet start. The TUI installed a logger that dropped *everything*, which
// also swallowed the WARN lines that explain a failed load or attach.
//
// The policy is therefore level based: WARN is kept, INFO and DEBUG are
// dropped, and only the destination of a kept line depends on the mode:
//
//   - headless: stderr, unchanged apart from the filtering;
//   - TUI: never stderr. While a trace is being set up the lines are handed to
//     the setup warning collector (see routeWarnings), which replays them as
//     warning rows in the dashboard (capped, truncated and without the
//     per-tracepoint skip noise, see libbpfRoute); outside that window they are
//     dropped because no warning sink exists to receive them.
type libbpfLogger struct {
	mu      sync.Mutex
	out     io.Writer
	tui     bool
	verbose bool
	// route, when set, receives kept WARN lines instead of the mode's default
	// destination. Only ever set in TUI mode, and only by routeWarnings and
	// the end function it returns: configure never touches it, because a TUI
	// restart starts the next setup while the cancelled one may still be
	// loading, and resetting the route there would drop the new session's
	// warnings.
	route *libbpfRoute
}

// libbpfRoute is one TUI setup session's share of the WARN stream. Its
// identity is the session token: end clears the logger's route only if it is
// still this one, so an older session finishing late cannot unhook a newer
// session's routing. All fields are guarded by libbpfLogger.mu.
type libbpfRoute struct {
	warn       func(...any)
	routed     int
	suppressed int
}

// libbpfLog is the process-wide logger. libbpf's print callback is a single
// process-global hook, so the state that steers it is global too.
var libbpfLog = &libbpfLogger{out: os.Stderr}

// init installs libbpf's print callback, exactly once, before any BPF module
// can be created, so no code path (headless modes, tests, tools importing this
// package) can reach libbpfgo's unfiltered default.
//
// bpf.SetLoggerCbs assigns a plain package variable that libbpf's own threads
// read without synchronisation, so it must never run while a module exists.
// The callback is therefore installed here and never again: the mode switches
// (setLibbpfLogging) only change libbpfLog's state, which log reads under its
// mutex.
func init() {
	bpf.SetLoggerCbs(bpf.Callbacks{Log: libbpfLog.log})
	setLibbpfLogging(false)
}

// setLibbpfLogging selects the level policy for the given mode. It is safe to
// call repeatedly (every TUI trace start does) and leaves warning routing
// alone: that belongs to the setup session that installed it.
func setLibbpfLogging(tui bool) {
	libbpfLog.configure(tui, libbpfDebugRequested(os.Getenv(libbpfDebugEnv)))
}

// libbpfDebugRequested reports whether the IOR_LIBBPF_DEBUG value asks for the
// full libbpf output. Empty, "0", "false", "no" and "off" (case-insensitive,
// surrounding blanks ignored) mean off so the variable can be exported
// unconditionally by scripts; any other value turns it on.
func libbpfDebugRequested(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}

func (l *libbpfLogger) configure(tui, verbose bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tui = tui
	// Verbose output is a headless-only escape hatch: it would tear the TUI.
	l.verbose = verbose && !tui
}

// routeWarnings sends the libbpf WARN lines of the current TUI trace setup to
// warn (the setup warning collector) and returns the function that ends the
// routing. In headless mode it is a no-op returning a no-op: those lines
// already go straight to stderr, where they are visible immediately and in
// order with ior's own status lines.
//
// The routing is scoped to the setup call because the collector is only
// drained once, when the event loop starts; anything logged later has no
// consumer and must not be appended to a collector nobody reads.
//
// Sessions can overlap: a TUI restart cancels the old session without waiting
// for it, so the next setup may begin while the previous one is still inside
// libbpf. The newest route wins, and end only unhooks the route it installed,
// so the older session finishing late leaves the newer routing intact. libbpf's
// print callback carries no session identity, hence lines logged during an
// overlap go to the newest route; what is guaranteed is that a collector never
// receives a line after its own end returned. warn is called with the logger's
// mutex held and from a different goroutine than the session's own setup code
// when sessions overlap, so it must be safe for concurrent use (setupWarnings
// is).
//
// Rows are shaped for the dashboard (see libbpfRoute.offer) and end appends
// one summary row when lines were suppressed.
func (l *libbpfLogger) routeWarnings(warn func(...any)) (end func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.tui {
		return func() {}
	}
	route := &libbpfRoute{warn: warn}
	l.route = route
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.route == route {
			l.route = nil
		}
		route.flush()
	}
}

// offer turns one libbpf WARN line into at most one warning row.
//
// Two classes would flood or blow up the dashboard, so they are shaped here
// rather than at the source (headless stderr still shows everything):
//
//   - "failed to determine tracepoint 'x/y' perf event ID": one line per
//     syscall tracepoint the running kernel lacks, dozens on an older kernel.
//     bpfSetupLog already reports each skipped tracepoint through the probe
//     manager (visible in the probes view) and deliberately keeps them out of
//     the warning rows, so they are dropped here without being counted as
//     suppressed.
//   - a failed program load is ONE WARN carrying the whole verifier log, so
//     every row is cut to its first line plus a "(N more lines)" marker and
//     to maxRoutedWarningBytes.
//
// Beyond maxRoutedWarnings rows the remainder is only counted.
func (r *libbpfRoute) offer(msg string) {
	msg = strings.TrimSuffix(msg, "\n")
	if isTracepointSkipWarning(msg) {
		return
	}
	if r.routed >= maxRoutedWarnings {
		r.suppressed++
		return
	}
	r.routed++
	r.warn(shortenWarning(msg, maxRoutedWarningBytes))
}

// flush emits the summary row for lines the cap held back.
func (r *libbpfRoute) flush() {
	if r.suppressed == 0 {
		return
	}
	r.warn(fmt.Sprintf("libbpf: %d further warning(s) not shown; -plain prints every libbpf warning on stderr", r.suppressed))
	r.suppressed = 0
}

// isTracepointSkipWarning recognises libbpf's per-tracepoint attach failure
// (perf_event_open_tracepoint in libbpf.c).
func isTracepointSkipWarning(msg string) bool {
	return strings.Contains(msg, "failed to determine tracepoint '") &&
		strings.Contains(msg, "perf event ID")
}

// shortenWarning keeps the first line of msg and at most limit bytes of it,
// cut on a rune boundary, and says how much was left out.
func shortenWarning(msg string, limit int) string {
	first, rest, multiline := strings.Cut(msg, "\n")
	extra := ""
	if multiline {
		extra = fmt.Sprintf(" ... (%d more lines)", strings.Count(rest, "\n")+1)
	}
	if len(first) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(first[cut]) {
			cut--
		}
		first = first[:cut] + "..."
	}
	return first + extra
}

// log is the libbpf print callback. libbpf hands over complete lines that
// already carry the "libbpf: " prefix and a trailing newline.
func (l *libbpfLogger) log(level int, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level != bpf.LibbpfWarnLevel && !l.verbose {
		return
	}
	switch {
	case l.tui && l.route != nil:
		l.route.offer(msg)
	case l.tui:
		// No warning sink in reach: stderr belongs to the dashboard.
	default:
		// Best effort like every other status write: a closed stderr must not
		// take the trace down.
		_, _ = io.WriteString(l.out, msg)
	}
}
