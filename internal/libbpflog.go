package internal

import (
	"io"
	"os"
	"strings"
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
)

// libbpfDebugEnv re-enables the libbpf INFO and DEBUG output that ior drops by
// default (any non-empty value other than "0"). It is read for the headless
// modes only: in TUI mode stderr is the Bubble Tea screen, so unfiltered
// libbpf lines would corrupt it.
const libbpfDebugEnv = "IOR_LIBBPF_DEBUG"

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
//     warning rows in the dashboard; outside that window they are dropped
//     because no warning sink exists to receive them.
type libbpfLogger struct {
	mu      sync.Mutex
	out     io.Writer
	tui     bool
	verbose bool
	// sink, when set, receives kept WARN lines (trailing newline trimmed)
	// instead of the mode's default destination. Only ever set in TUI mode.
	sink func(...any)
}

// libbpfLog is the process-wide logger. libbpf's print callback is a single
// process-global hook, so the state that steers it is global too.
var libbpfLog = &libbpfLogger{out: os.Stderr}

// init installs the headless policy before any BPF module can be created, so
// no code path (headless modes, tests, tools importing this package) can reach
// libbpfgo's unfiltered default. startTUITrace switches to the TUI variant.
func init() {
	setLibbpfLogging(false)
}

// setLibbpfLogging installs the level filter for the given mode as libbpf's
// print callback. It is safe to call repeatedly (every TUI trace start does)
// and clears any warning routing left over from an earlier session.
func setLibbpfLogging(tui bool) {
	libbpfLog.configure(tui, libbpfDebugRequested(os.Getenv(libbpfDebugEnv)))
	bpf.SetLoggerCbs(bpf.Callbacks{Log: libbpfLog.log})
}

// libbpfDebugRequested reports whether the IOR_LIBBPF_DEBUG value asks for the
// full libbpf output. Empty and "0" mean off so the variable can be exported
// unconditionally by scripts.
func libbpfDebugRequested(value string) bool {
	return value != "" && value != "0"
}

func (l *libbpfLogger) configure(tui, verbose bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tui = tui
	// Verbose output is a headless-only escape hatch: it would tear the TUI.
	l.verbose = verbose && !tui
	l.sink = nil
}

// routeWarnings sends the libbpf WARN lines of the current TUI trace setup to
// warn (the setup warning collector) and returns the function that ends the
// routing. In headless mode it is a no-op returning a no-op: those lines
// already go straight to stderr, where they are visible immediately and in
// order with ior's own status lines.
//
// The routing is scoped to the setup call because the collector is only
// drained once, when the event loop starts; anything logged later has no
// consumer and must not be appended to a collector nobody reads (nor race
// with the drain, which is unlocked by design).
func (l *libbpfLogger) routeWarnings(warn func(...any)) (end func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.tui {
		return func() {}
	}
	l.sink = warn
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.sink = nil
	}
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
	case l.tui && l.sink != nil:
		l.sink(strings.TrimSuffix(msg, "\n"))
	case l.tui:
		// No warning sink in reach: stderr belongs to the dashboard.
	default:
		// Best effort like every other status write: a closed stderr must not
		// take the trace down.
		_, _ = io.WriteString(l.out, msg)
	}
}
