package internal

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ior/internal/collapse"
	"ior/internal/csvlist"
	"ior/internal/flamegraph"
	"ior/internal/textsafe"
)

// RunCollapsedConverter implements the `ior collapsed` subcommand: it reads
// an .ior.zst recording and writes flamegraph.pl-ready collapsed stacks to
// w (stdout in production). The recording format is a zstd-compressed stream
// (magic, gob header with the tracepoint-name table, gob records), not
// collapsed text, so this derivation is the documented
// bridge for offline FlameGraph rendering:
//
//	ior collapsed trace.ior.zst | flamegraph.pl > trace.svg
//
// Records whose selected fields are all empty are counted under an
// "[unknown]" frame so the total weight is preserved (the event count with
// the default -count count, the sum of that counter otherwise); zero-weight
// records are omitted.
//
// With the default -escape=auto the frames are escaped with textsafe.Escape
// (control and invisible runes shown as \x1b, \u202e, ...) when w is a
// terminal, and piped or redirected output keeps the raw bytes;
// -escape=always also escapes into pipes (| less -R), -escape=never never
// escapes. An invalid -escape value is a flag parse error. Whatever the
// mode, a line break inside a frame is always written as \x0a / \x0d so a
// traced path cannot forge extra collapsed-stack lines (see
// flamegraph.WriteCollapsedStacks).
func RunCollapsedConverter(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("collapsed", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fields := fs.String("fields", strings.Join(collapse.DefaultFields(), ","),
		"comma-separated frame fields in stack order (one of: "+strings.Join(collapse.ValidFields(), ",")+
			"); all-empty records are counted under [unknown] to keep the total weight; zero-weight records are omitted")
	count := fs.String("count", collapse.DefaultCountField(),
		"counter metric used as the sample weight (one of: "+strings.Join(collapse.ValidCountFields(), ",")+")")
	escapeMode := textsafe.EscapeAuto
	fs.Var(&escapeMode, "escape",
		"when to escape control and invisible characters in frames (`mode`): auto (only when stdout is a terminal; a pipe such as | less -R gets raw bytes), always, or never")

	if err := fs.Parse(args); err != nil {
		// -h/-help: print the converter usage and exit cleanly instead of
		// surfacing the help request as a parse error.
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(w)
			fs.Usage()
			return nil
		}
		return fmt.Errorf("parse flags: %w (usage: ior collapsed [-fields f1,f2] [-count metric] [-escape auto|always|never] <trace.ior.zst>)", err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("expected exactly one .ior.zst recording argument (usage: ior collapsed [-fields f1,f2] [-count metric] [-escape auto|always|never] <trace.ior.zst>)")
	}

	return flamegraph.WriteCollapsedStacks(w, fs.Arg(0), flamegraph.CollapsedOptions{
		// Blank/comma-only -fields yields nil, which WriteCollapsedStacks
		// treats as collapse.DefaultFields.
		Fields:     csvlist.Split(*fields),
		CountField: *count,
		// Frames are traced comm names and paths: by default escape them
		// when w is a terminal so they cannot inject escape sequences, and
		// keep them raw when piped into flamegraph.pl or redirected to a
		// file (line breaks excepted, which the collapsed writer always
		// encodes); -escape=always|never overrides the terminal check.
		Escape: escapeMode.Escaper(w),
		// Remarks about the recording (a sampled run) go to stderr, which
		// keeps stdout pure collapsed text for flamegraph.pl.
		Notice: func(line string) { _, _ = fmt.Fprintln(os.Stderr, line) },
	})
}
