package flamegraph

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"ior/internal/collapse"
)

// CollapsedOptions controls how an .ior.zst recording is derived into
// flamegraph.pl-ready collapsed stacks.
type CollapsedOptions struct {
	// Fields names the record fields used as frames, in stack order
	// (any of collapse.ValidFields). Empty means collapse.DefaultFields.
	Fields []string
	// CountField is the counter metric used as the sample weight
	// (any of collapse.ValidCountFields). Empty means "count".
	CountField string
	// Escape, when non-nil, rewrites each frame path just before it is
	// written. `ior collapsed` sets it to textsafe.Escape when stdout is a
	// terminal, because frames are traced comm names and paths that could
	// otherwise inject escape sequences into the operator's terminal. nil
	// writes the traced bytes, which is what flamegraph.pl in a pipe needs,
	// except for the line breaks encodeCollapsedFrame always rewrites
	// because they are structural in the collapsed format. Aggregation and
	// sorting use the format-encoded (never the Escape-rewritten) paths.
	Escape func(string) string
	// Notice, when non-nil, receives one human-readable line per remark about
	// the recording that the collapsed stacks cannot carry themselves - today
	// that a recording of a sampling run holds only a sample of the sampled
	// syscalls. `ior collapsed` writes them to stderr, keeping stdout pure
	// collapsed text for flamegraph.pl. nil drops them.
	Notice func(line string)
}

func (o CollapsedOptions) normalize() (CollapsedOptions, error) {
	fields := o.Fields
	if len(fields) == 0 {
		fields = collapse.DefaultFields()
	}
	fields, err := normalizeLiveTrieFields(fields)
	if err != nil {
		return CollapsedOptions{}, fmt.Errorf("invalid collapsed fields: %w", err)
	}

	countField := strings.TrimSpace(o.CountField)
	if countField == "" {
		countField = collapse.DefaultCountField()
	}
	if !collapse.IsValidCountField(countField) {
		return CollapsedOptions{}, fmt.Errorf("invalid count field %q", countField)
	}
	return CollapsedOptions{Fields: fields, CountField: countField, Escape: o.Escape, Notice: o.Notice}, nil
}

// WriteCollapsedStacks reads an .ior.zst recording and writes collapsed-stack
// lines ("frame;frame;... weight") to w, ready for flamegraph.pl:
//
//	ior collapsed trace.ior.zst | flamegraph.pl > trace.svg
//
// The .ior.zst artifact is a zstd-compressed stream (magic, gob header with the
// tracepoint-name table, gob records), not collapsed text; this function is
// the documented bridge to external FlameGraph tooling. Frames mirror the in-TUI flamegraph exactly (same record fields
// and the same per-field splitting), records mapping to identical frame
// paths are summed into one sample, and lines are sorted so the output is
// deterministic. Records with a zero sample weight are skipped: they would
// render zero-width in any flamegraph. A record whose selected fields all
// render empty (for example -fields path on a file whose name is empty, or
// -fields comm with an empty comm) is NOT skipped, because its weight is
// positive and dropping it would make the collapsed total weight differ from the
// recording's (the event count for -count count, the sum of the chosen
// counter otherwise) and from the other outputs (CSV, Parquet). It is
// counted under the single placeholder frame collapsedEmptyFrame instead,
// since a collapsed line cannot have an empty stack.
//
// Frame text is traced, attacker-controlled data, so every frame is made
// structurally inert before it is joined, whatever the Escape option says
// (see encodeCollapsedFrame): the ';' separator never occurs inside a frame
// because buildFrames already splits on it, LF and CR are encoded so a
// frame cannot start a forged weighted line, and the weight is always the
// last space-separated token, so a frame ending in " 999" cannot change it.
func WriteCollapsedStacks(w io.Writer, filename string, opts CollapsedOptions) error {
	opts, err := opts.normalize()
	if err != nil {
		return err
	}

	records, samples, err := LoadRecording(filename)
	if err != nil {
		return err
	}
	// A sampled recording's weights are those of the traced sample, not of the
	// population: say so, or the flamegraph reads as the whole workload.
	if opts.Notice != nil {
		for _, line := range samples.Lines() {
			opts.Notice("ior collapsed: " + line)
		}
	}

	totals := make(map[string]uint64)
	for record := range records {
		value, err := record.Cnt.ValueByName(opts.CountField)
		if err != nil {
			return err
		}
		if value == 0 {
			continue
		}
		frames := buildFrames(record, opts.Fields)
		if len(frames) == 0 {
			frames = append(frames, collapsedEmptyFrame)
		}
		for i, frame := range frames {
			frames[i] = encodeCollapsedFrame(frame)
		}
		totals[strings.Join(frames, ";")] += value
	}

	return writeCollapsedLines(w, totals, opts.Escape)
}

// collapsedEmptyFrame is the frame a record with a positive weight gets when
// none of the selected fields yields a frame (see WriteCollapsedStacks). It is
// free of ';', whitespace and line breaks, so it is structurally inert like
// every other frame. It is not collision-free: a comm, or a relative path
// component (appendPathFrames does not require a leading '/'), that equals
// "[unknown]" yields the same first frame and merges into the placeholder's
// line, which merely adds up the weights and cannot forge a stack. A
// collision-free placeholder is impossible in the collapsed text format,
// because a ';' inside a frame would be split by flamegraph.pl.
const collapsedEmptyFrame = "[unknown]"

// encodeCollapsedFrame rewrites the characters of one frame that are
// structural in the line-based collapsed format ("frame;frame weight\n")
// and that buildFrames does not already split on: LF becomes the four
// characters `\x0a` and CR becomes `\x0d`. A traced path such as
// "x\n/evil;frame 999999999" would otherwise end the current line and forge
// a separately weighted stack in flamegraph.pl's input; CR is encoded too
// because CRLF-aware consumers treat it as part of a line break. The
// notation is textsafe.Escape's, so -escape=always output is unchanged by
// this pre-encoding (Escape does not double backslashes and leaves the
// already-escaped text alone). Like Escape it is not a full quoting scheme:
// a frame literally containing `\x0a` reads the same as one containing LF,
// and both aggregate into one sample. A clean frame is returned as is
// without allocating, so ordinary output stays byte-identical.
func encodeCollapsedFrame(frame string) string {
	if !strings.ContainsAny(frame, "\n\r") {
		return frame
	}
	return collapsedLineBreakEncoder.Replace(frame)
}

// collapsedLineBreakEncoder implements encodeCollapsedFrame's rewrite.
var collapsedLineBreakEncoder = strings.NewReplacer("\n", `\x0a`, "\r", `\x0d`)

// writeCollapsedLines writes one "path weight" line per entry of totals,
// sorted by encoded path so the output is deterministic. escape (optional) is
// applied to the path only when writing; see CollapsedOptions.Escape.
func writeCollapsedLines(w io.Writer, totals map[string]uint64, escape func(string) string) error {
	paths := make([]string, 0, len(totals))
	for path := range totals {
		paths = append(paths, path)
	}
	slices.Sort(paths)

	for _, path := range paths {
		shown := path
		if escape != nil {
			shown = escape(path)
		}
		if _, err := fmt.Fprintf(w, "%s %d\n", shown, totals[path]); err != nil {
			return fmt.Errorf("write collapsed stacks: %w", err)
		}
	}
	return nil
}
