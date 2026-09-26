package internal

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"ior/internal/collapse"
	"ior/internal/csvlist"
	"ior/internal/flamegraph"
)

// RunCollapsedConverter implements the `ior collapsed` subcommand: it reads
// an .ior.zst recording and writes flamegraph.pl-ready collapsed stacks to
// w (stdout in production). The recording format is a zstd-compressed gob
// record map, not collapsed text, so this derivation is the documented
// bridge for offline FlameGraph rendering:
//
//	ior collapsed trace.ior.zst | flamegraph.pl > trace.svg
func RunCollapsedConverter(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("collapsed", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fields := fs.String("fields", strings.Join(collapse.DefaultFields(), ","),
		"comma-separated frame fields in stack order (one of: "+strings.Join(collapse.ValidFields(), ",")+")")
	count := fs.String("count", collapse.DefaultCountField(),
		"counter metric used as the sample weight (one of: "+strings.Join(collapse.ValidCountFields(), ",")+")")

	if err := fs.Parse(args); err != nil {
		// -h/-help: print the converter usage and exit cleanly instead of
		// surfacing the help request as a parse error.
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(w)
			fs.Usage()
			return nil
		}
		return fmt.Errorf("parse flags: %w (usage: ior collapsed [-fields f1,f2] [-count metric] <trace.ior.zst>)", err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("expected exactly one .ior.zst recording argument (usage: ior collapsed [-fields f1,f2] [-count metric] <trace.ior.zst>)")
	}

	return flamegraph.WriteCollapsedStacks(w, fs.Arg(0), flamegraph.CollapsedOptions{
		// Blank/comma-only -fields yields nil, which WriteCollapsedStacks
		// treats as collapse.DefaultFields.
		Fields:     csvlist.Split(*fields),
		CountField: *count,
	})
}
